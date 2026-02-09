"""Module 4 — Channel / DM Policy Auditor.

Reads the OpenClaw configuration and audits channel and DM policies:
- DM policy per channel (should be "pairing", not "open")
- Group requireMention (should be true)
- Session isolation / dmScope (should be "per-channel-peer")
- Overly permissive wildcard channel configs
- Channels with no authentication requirements
"""

import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

from .base import BaseModule, Finding


class ChannelAuditor(BaseModule):
    name = "channel_auditor"
    description = "Audit channel and DM policies for security misconfigurations"

    def __init__(self, config_override: Optional[Dict[str, Any]] = None):
        """
        Args:
            config_override: If provided, use this dict instead of loading from disk.
                             Useful for testing.
        """
        self._config_override = config_override

    def _load_config(self, openclaw_path: str) -> Optional[Dict[str, Any]]:
        if self._config_override is not None:
            return self._config_override

        # Check env override first
        env_path = os.environ.get("OPENCLAW_CONFIG")
        if env_path:
            p = Path(env_path)
        else:
            p = Path(openclaw_path) / "openclaw.json"

        if not p.exists():
            return None
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            return None

    def scan(self, openclaw_path: str) -> List[Finding]:
        findings: List[Finding] = []
        config = self._load_config(openclaw_path)

        if config is None:
            findings.append(Finding(
                severity="MEDIUM",
                category="Channel Policy",
                title="OpenClaw config not found",
                description="Could not load openclaw.json for channel policy audit.",
                remediation="Ensure openclaw.json exists in the .openclaw directory.",
            ))
            return findings

        config_path = os.environ.get("OPENCLAW_CONFIG",
                                     str(Path(openclaw_path) / "openclaw.json"))

        # --- Global DM policy ---
        dm = config.get("dm_policy", config.get("dmPolicy", {}))
        self._check_dm_policy(dm, "global", config_path, findings)

        # --- Global session isolation ---
        self._check_session_isolation(config, config_path, findings)

        # --- Per-channel configs ---
        channels = config.get("channels", {})
        for ch_name, ch_cfg in channels.items():
            self._check_channel(ch_name, ch_cfg, config_path, findings)

        # --- Wildcard / default channel ---
        if "*" in channels:
            wc = channels["*"]
            self._check_wildcard(wc, config_path, findings)

        return findings

    # ------------------------------------------------------------------
    def _check_dm_policy(self, dm: Dict[str, Any], scope: str,
                         config_path: str, findings: List[Finding]) -> None:
        # dm_mode / policy should be "pairing"
        mode = dm.get("mode", dm.get("policy", dm.get("allowDMs")))
        if mode is True or (isinstance(mode, str) and mode.lower() == "open"):
            findings.append(Finding(
                severity="HIGH",
                category="Channel Policy",
                title=f"DM policy is 'open' ({scope})",
                description=(
                    f"The {scope} DM policy allows unsolicited direct messages. "
                    "This lets unknown users interact with the agent without pairing."
                ),
                remediation=(
                    'Set dm_policy.mode to "pairing" to require explicit pairing '
                    "before DM interactions."
                ),
                affected_path=config_path,
            ))

        # allowUnsolicited
        if dm.get("allowUnsolicited", False):
            findings.append(Finding(
                severity="HIGH",
                category="Channel Policy",
                title=f"Unsolicited DMs allowed ({scope})",
                description=(
                    f"The {scope} config allows unsolicited DMs, meaning anyone "
                    "can message the agent without prior authorization."
                ),
                remediation='Set "allowUnsolicited" to false.',
                affected_path=config_path,
            ))

        # requireMention for groups
        if dm.get("requireMention") is False:
            findings.append(Finding(
                severity="MEDIUM",
                category="Channel Policy",
                title=f"requireMention is disabled ({scope})",
                description=(
                    f"The {scope} config does not require mentions in groups. "
                    "The agent will respond to all messages, increasing attack surface."
                ),
                remediation='Set "requireMention" to true in group contexts.',
                affected_path=config_path,
            ))

    def _check_session_isolation(self, config: Dict[str, Any],
                                 config_path: str,
                                 findings: List[Finding]) -> None:
        dm_scope = (config.get("dmScope")
                    or config.get("dm_scope")
                    or config.get("sessionIsolation", {}).get("dmScope"))
        if dm_scope and dm_scope != "per-channel-peer":
            findings.append(Finding(
                severity="MEDIUM",
                category="Channel Policy",
                title=f"dmScope is '{dm_scope}' (should be 'per-channel-peer')",
                description=(
                    f"Session isolation dmScope is set to '{dm_scope}'. "
                    "Without per-channel-peer isolation, context may leak between "
                    "conversations from different users or channels."
                ),
                remediation='Set "dmScope" to "per-channel-peer".',
                affected_path=config_path,
            ))

    def _check_channel(self, name: str, cfg: Dict[str, Any],
                       config_path: str, findings: List[Finding]) -> None:
        # Per-channel DM policy
        dm = cfg.get("dm_policy", cfg.get("dmPolicy", {}))
        if dm:
            self._check_dm_policy(dm, f"channel '{name}'", config_path, findings)

        # requireMention at channel level
        if cfg.get("requireMention") is False:
            findings.append(Finding(
                severity="MEDIUM",
                category="Channel Policy",
                title=f"requireMention disabled for channel '{name}'",
                description=f"Channel '{name}' does not require mentions.",
                remediation='Set "requireMention" to true.',
                affected_path=config_path,
            ))

        # No auth
        auth = cfg.get("auth", cfg.get("authentication", {}))
        if isinstance(auth, dict) and not auth.get("enabled", True):
            findings.append(Finding(
                severity="HIGH",
                category="Channel Policy",
                title=f"No authentication for channel '{name}'",
                description=f"Channel '{name}' has authentication disabled.",
                remediation="Enable authentication for all channels.",
                affected_path=config_path,
            ))
        elif isinstance(auth, bool) and not auth:
            findings.append(Finding(
                severity="HIGH",
                category="Channel Policy",
                title=f"No authentication for channel '{name}'",
                description=f"Channel '{name}' has authentication disabled.",
                remediation="Enable authentication for all channels.",
                affected_path=config_path,
            ))

    def _check_wildcard(self, wc: Dict[str, Any], config_path: str,
                        findings: List[Finding]) -> None:
        findings.append(Finding(
            severity="MEDIUM",
            category="Channel Policy",
            title="Wildcard (*) channel configuration detected",
            description=(
                "A wildcard channel config applies to ALL channels by default. "
                "This may be overly permissive if not carefully scoped."
            ),
            remediation=(
                "Review the wildcard config and consider explicit per-channel "
                "configurations instead."
            ),
            affected_path=config_path,
        ))

        # Check wildcard DM policy too
        dm = wc.get("dm_policy", wc.get("dmPolicy", {}))
        if dm:
            self._check_dm_policy(dm, "wildcard (*)", config_path, findings)
