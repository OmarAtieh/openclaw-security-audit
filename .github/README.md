# GitHub Actions Workflows

This directory contains CI/CD workflows for the OpenClaw Security Audit Tool.

## Available Workflows

### `security-audit.yml` — OpenClaw Security Audit

**Purpose:** Demonstrates how to integrate the security audit tool into a CI/CD pipeline.

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main`
- Daily at 2 AM UTC (scheduled)
- Manual trigger (workflow_dispatch)

**What it does:**
1. Downloads the latest release of the audit tool
2. Runs security scan on the OpenClaw installation
3. Generates JSON and Markdown reports
4. Uploads reports as artifacts (90-day retention)
5. Comments on PRs with findings
6. **Fails the build** if critical issues found
7. **Warns** if high severity issues found
8. **Passes** if no critical/high issues

**Exit codes:**
- `0` — Clean, no critical/high issues
- `1` — High severity issues (warns but doesn't fail)
- `2` — Critical issues (fails the build)

**Usage in your project:**

1. Copy `.github/workflows/security-audit.yml` to your repo
2. Adjust the `--openclaw-dir` path to match your setup
3. Customize severity thresholds if needed
4. Commit and push

**Example output:**

```
🛡️ OpenClaw Security Audit Results

# OpenClaw Security Audit Report

**Scan Time:** 2026-02-09T03:00:00.000000  
**OpenClaw Directory:** `/home/runner/.openclaw`

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 **CRITICAL** | 0 |
| 🟠 **HIGH** | 2 |
| 🟡 **MEDIUM** | 3 |
```

## Customization

### Change Severity Thresholds

To fail on HIGH issues (not just CRITICAL):

```yaml
- name: Check Severity and Fail if High or Critical
  if: steps.scan.outputs.exit_code != '0'
  run: |
    echo "::error::Security issues found!"
    exit 1
```

### Scan Multiple Directories

```yaml
- name: Run Security Scan
  run: |
    for dir in /opt/openclaw-prod /opt/openclaw-staging; do
      python3 audit.py --openclaw-dir $dir --output-json audit-$(basename $dir).json
    done
```

### Send Slack Notifications

Add after the scan step:

```yaml
- name: Send Slack Notification
  if: steps.scan.outputs.exit_code != '0'
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "⚠️ OpenClaw security issues found in ${{ github.repository }}"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### Save to S3

```yaml
- name: Upload to S3
  uses: aws-actions/configure-aws-credentials@v2
  with:
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    aws-region: us-east-1
    
- run: |
    aws s3 cp audit-report.json s3://my-bucket/security-audits/$(date +%Y-%m-%d)/
```

## Best Practices

1. **Run on schedule** — Daily scans catch configuration drift
2. **Fail on critical** — Block deployments with critical issues
3. **Archive reports** — Keep audit trail for compliance
4. **Review regularly** — Don't ignore warnings
5. **Update malicious DB** — Pull latest tool version weekly

## Security Considerations

- The workflow runs in GitHub's hosted runners (Ubuntu)
- No secrets are exposed in logs
- Reports may contain sensitive info — review artifact permissions
- Consider using self-hosted runners for production configs

## Support

Questions? Open an issue: https://github.com/your-org/openclaw-security-audit/issues
