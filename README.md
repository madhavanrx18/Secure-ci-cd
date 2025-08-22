# Enhanced DevSecOps Security Scanner

A comprehensive security scanning tool that integrates multiple security analysis techniques to identify vulnerabilities in software repositories. The scanner performs Software Composition Analysis (SCA), secrets detection, Static Application Security Testing (SAST), and Insecure Direct Object Reference (IDOR) vulnerability detection with intelligent risk assessment and CVE scoring.

## Features

### Core Security Scanning
- **Software Composition Analysis (SCA)**: Identifies known vulnerabilities in dependencies using Safety
- **Secrets Detection**: Scans for exposed credentials and sensitive information using Gitleaks
- **Static Application Security Testing (SAST)**: Analyzes source code for security vulnerabilities using Bandit
- **IDOR Detection**: Identifies Insecure Direct Object Reference vulnerabilities using Semgrep with custom rules

### Risk Assessment
- **CVE-based Scoring**: Fetches real-time CVE data from NIST NVD API for accurate risk assessment
- **Contextual Risk Adjustment**: Adjusts risk scores based on vulnerability age, exploitability, and environment context
- **Intelligent Action Recommendations**: Provides actionable guidance with deployment decisions (Block, Warn, Monitor, Ignore)

### Advanced Analysis
- **Pattern-specific IDOR Detection**: Custom Semgrep rules for detecting various IDOR patterns
- **Risk-based Decision Making**: Automated deployment recommendations based on aggregated security findings
- **Comprehensive Reporting**: Detailed JSON reports with risk breakdowns and remediation guidance

## Installation

### Prerequisites
- Python 3.8 or higher
- Git

### Required Tools
Install the following security tools:

```bash
# Install Python dependencies
pip install safety bandit gitleaks semgrep aiohttp gitpython

# Alternative installation methods:
# Safety: pip install safety
# Bandit: pip install bandit
# Gitleaks: Install from https://github.com/zricethezav/gitleaks
# Semgrep: pip install semgrep
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

Required packages:
- aiohttp
- gitpython
- requests
- pathlib
- asyncio

## Configuration

Create a configuration file `config.json` to customize scanner behavior:

```json
{
  "tools": {
    "sca": "safety",
    "secrets": "gitleaks",
    "sast": "bandit",
    "idor": "semgrep"
  },
  "risk_thresholds": {
    "critical_cvss_min": 9.0,
    "high_cvss_min": 7.0,
    "medium_cvss_min": 4.0,
    "block_on_critical": true,
    "block_on_high_count": 5
  },
  "semgrep_config": {
    "rulesets": [
      "p/owasp-top-10",
      "p/security-audit",
      "p/insecure-transport"
    ],
    "custom_idor_rules": true,
    "timeout": 300
  },
  "cve_sources": {
    "nvd_api_key": "your_nvd_api_key_optional"
  }
}
```

## Usage

### Basic Usage
```python
import asyncio
from enhanced_security_scanner import EnhancedSecurityScanner

async def main():
    scanner = EnhancedSecurityScanner()
    results = await scanner.run_security_checks("https://github.com/user/repo.git")
    scanner.save_enhanced_report()

asyncio.run(main())
```

### Command Line Usage
```bash
python enhanced_security_scanner.py
```

### Webhook Integration
```python
# For CI/CD webhook integration
results = await trigger_enhanced_security_scan(
    repo_name="user/repo",
    branch="main",
    commit_id="abc123",
    clone_url="https://github.com/user/repo.git"
)
```

## IDOR Detection Rules

The scanner includes custom Semgrep rules for detecting IDOR vulnerabilities:

- **Direct Object Access**: Detects unprotected database queries using user input
- **Missing Authorization**: Identifies object access without ownership validation
- **Parameter Manipulation**: Catches unsafe use of user-controlled parameters
- **File Path Manipulation**: Detects potential path traversal vulnerabilities
- **API Endpoint Exposure**: Identifies unprotected API endpoints
- **Session Manipulation**: Detects session-based IDOR risks

## Output Format

### Risk Levels
- **CRITICAL**: Immediate security threat requiring deployment block
- **HIGH**: Significant security risk requiring prompt attention
- **MEDIUM**: Moderate risk requiring monitoring and scheduled fixes
- **LOW**: Minor security concerns
- **INFO**: Informational findings

### Actions
- **BLOCK**: Prevent deployment due to critical security issues
- **WARN**: Allow deployment with warnings about security risks
- **MONITOR**: Deploy with continued monitoring of identified issues
- **IGNORE**: Proceed without security concerns

### Report Structure
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "sca": {
    "findings": [],
    "risk_summary": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, "LOW": 1},
    "actions": {"BLOCK": 0, "WARN": 2, "MONITOR": 5, "IGNORE": 1}
  },
  "secrets": { /* ... */ },
  "sast": { /* ... */ },
  "idor": {
    "findings": [],
    "rules_used": ["p/owasp-top-10", "custom_idor_rules"],
    "risk_summary": { /* ... */ }
  },
  "summary": {
    "overall_decision": "WARN",
    "risk_score": 65.2,
    "deployment_recommendation": "PROCEED WITH CAUTION: 2 high-risk issues found"
  },
  "recommendations": []
}
```

## Integration

### CI/CD Pipeline Integration
The scanner can be integrated into CI/CD pipelines to automatically assess security risks:

1. **GitHub Actions**: Add as a workflow step
2. **Jenkins**: Include in pipeline scripts
3. **GitLab CI**: Add to `.gitlab-ci.yml`
4. **Azure DevOps**: Include in pipeline YAML

### Webhook Support
Supports webhook integration for automatic scanning on repository events:

```python
# Example webhook handler
@app.post("/webhook/security-scan")
async def handle_webhook(payload: dict):
    results = await trigger_enhanced_security_scan(
        repo_name=payload["repository"]["full_name"],
        branch=payload["ref"].split("/")[-1],
        commit_id=payload["head_commit"]["id"]
    )
    return results
```

## Limitations

- SCA scanning requires `requirements.txt` files for Python projects
- CVE lookup requires internet connectivity for real-time data
- Semgrep IDOR detection is primarily designed for Python codebases
- API rate limits may apply for CVE data fetching without API keys

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request



## Support

For issues, questions, or contributions, please create an issue in the project repository.
