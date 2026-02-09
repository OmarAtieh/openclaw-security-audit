# Contributing to OpenClaw Security Audit Tool

Thank you for considering contributing! This project aims to improve OpenClaw security for everyone.

## 🎯 Types of Contributions

### 1. New Security Checks
Add detection for new vulnerabilities or misconfigurations.

**Example:**
```python
def check_new_feature(self):
    """Check for XYZ security issue"""
    # Implementation
    self.add_finding(
        severity="HIGH",
        category="Your Category",
        title="Short descriptive title",
        description="Detailed explanation of the issue",
        remediation="Step-by-step fix instructions",
        affected_path="/path/to/file"  # Optional
    )
```

### 2. Malicious Skill Signatures
Update `known_malicious.json` with new threats.

### 3. Documentation
Improve README, add examples, write tutorials.

### 4. Bug Fixes
Fix issues reported on GitHub.

## 🔧 Development Setup

1. **Fork and clone:**
   ```bash
   git clone https://github.com/your-username/openclaw-security-audit.git
   cd openclaw-security-audit
   ```

2. **Create a branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes** and test:
   ```bash
   ./audit.py  # Run locally
   ```

4. **Commit with clear messages:**
   ```bash
   git commit -m "Add check for XYZ vulnerability"
   ```

5. **Push and create PR:**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📋 Code Style

- Follow **PEP 8** style guide
- Use **type hints** for all functions
- Add **docstrings** to all methods
- Keep line length ≤ 100 characters
- Use descriptive variable names

## ✅ Pull Request Checklist

Before submitting:

- [ ] Code follows PEP 8 style
- [ ] Added type hints
- [ ] Added docstrings
- [ ] Tested on real OpenClaw deployment
- [ ] Updated README if adding new features
- [ ] Updated `known_malicious.json` if adding signatures
- [ ] No external dependencies (stdlib only)
- [ ] Works on Linux (Ubuntu/Debian minimum)

## 🐛 Reporting Bugs

Use GitHub Issues with:

1. **Clear title** describing the issue
2. **Steps to reproduce**
3. **Expected vs actual behavior**
4. **Environment** (OS, Python version, OpenClaw version)
5. **Logs/screenshots** if applicable

## 🔒 Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Email: security@yourcompany.com

Include:
- Detailed description
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We'll respond within 48 hours.

## 📜 License

By contributing, you agree your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be:
- Listed in README acknowledgments
- Credited in release notes
- Appreciated by the community!

---

**Questions?** Open a [Discussion](https://github.com/your-org/openclaw-security-audit/discussions)
