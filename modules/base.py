"""Base module interface for security scanners."""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any


@dataclass
class Finding:
    """Security finding with severity and details."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    remediation: str
    affected_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseModule:
    """Base class for all security scanner modules.

    Subclasses must implement ``scan(openclaw_path) -> list[Finding]``.
    """

    name: str = "base"
    description: str = ""

    def scan(self, openclaw_path: str) -> List[Finding]:
        """Run the scan and return a list of findings.

        Args:
            openclaw_path: Path to the ``.openclaw`` directory.

        Returns:
            List of Finding objects.
        """
        raise NotImplementedError

    # Convenience helpers shared across modules
    @staticmethod
    def _load_json(path: str) -> Optional[Any]:
        """Load a JSON file, returning None on any error."""
        import json
        from pathlib import Path
        p = Path(path)
        if not p.exists():
            return None
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            return None
