# CI CD Security Scanner

## Overview

**CI CD Security Scanner** is a composite security analysis tool combining:

* Software Composition Analysis (SCA) with CVE contextual scoring
* Static Application Security Testing (SAST)
* Secret detection
* IDOR (Insecure Direct Object Reference) pattern detection

It integrates external tools (`safety`, `bandit`, `gitleaks`, `semgrep`) and enriches their findings with risk classification, contextual weighting, and actionable recommendations to drive deployment decisions.

## Key Features

* CVE enrichment from NVD with score adjustment based on recency, exploitability, and context (e.g., production / internet-facing)
* IDOR detection via Semgrep with custom rule generation and pattern classification
* Secrets scanning with risk tiers and automatic action suggestions
* SAST analysis via Bandit with severity/confidence mapping
* Aggregated summary, risk assessment, and ranked recommendations
* Deployment decision logic (BLOCK / WARN / MONITOR / ALLOW)
* Exportable JSON report with metadata and detailed findings

## Prerequisites

* Python 3.8+
* Installed CLI tools (must be on `PATH`):

  * `safety`
  * `bandit`
  * `gitleaks`
  * `semgrep`
* Git (used by GitPython)
* Python dependencies (can be installed via pip):

  ```sh
  pip install aiohttp requests GitPython
  ```

## Installation

1. Clone or copy the repository containing this script.

2. Install required Python packages:

   ```sh
   pip install -r requirements.txt
   ```

   *If `requirements.txt` is not present, at minimum:*

   ```sh
   pip install aiohttp requests GitPython
   ```

3. Ensure external scanners are installed:

   ```sh
   pip install semgrep bandit safety gitleaks
   ```

## Configuration

The scanner uses a JSON configuration (optional). Default settings are embedded; to override, supply a config file path when instantiating `EnhancedSecurityScanner`.

Example custom `config.json` overrides:

```json
{
  "risk_thresholds": {
    "critical_cvss_min": 9.0,
    "block_on_critical": true,
    "recent_cve_days": 45
  },
  "semgrep_config": {
    "custom_idor_rules": true,
    "rulesets": ["p/owasp-top-10"],
    "timeout": 200
  },
  "cve_sources": {
    "nvd_api_key": "YOUR_API_KEY"
  }
}
```

## Usage

### Programmatic (async)

```python
from enhanced_scanner import trigger_enhanced_security_scan
import asyncio

results = asyncio.run(
    trigger_enhanced_security_scan(
        repo_name="owner/repo",
        branch="main",
        commit_id="abcdef123456",
        clone_url="https://github.com/owner/repo.git",
        context={"environment": "production", "internet_facing": True}
    )
)
```

### CLI-style entry (as shipped)

Run the module directly to scan a hardcoded repository:

```sh
python enhanced_security_scanner.py
```

*(Adjust the script’s `repo_url` or refactor to accept CLI arguments if needed.)*

## Output

The primary output is a structured JSON report saved as:

```
enhanced_security_report_<repo>_<branch>_<timestamp>.json
```

### Top-level report sections

* `sca`, `secrets`, `sast`, `idor`: raw and enhanced findings per scan type, including risk summaries and suggested actions.
* `summary`: consolidated risk counts, overall decision, risk score, and deployment recommendation.
* `risk_assessment`: methodology, CVE-related metrics, and IDOR analysis breakdown.
* `recommendations`: prioritized remediation items with titles, descriptions, guidance, and estimated effort.
* `metadata`: repository/branch/commit/context of the scan.

## Risk Model

* **RiskLevel**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
* **Action**: `BLOCK`, `WARN`, `MONITOR`, `IGNORE`
* CVE scores are adjusted for:

  * Recency (e.g., CVEs published within configured days get extra weight)
  * Exploitability (multiplied if high)
  * Context (production/internet-facing increases score)
* IDOR findings are classified by pattern type with mapped risk and action logic.
* Secrets are bucketed into high/medium/low based on keyword matching in rule IDs.

## Deployment Decision Logic

Overall decision is derived from aggregated actions:

* `BLOCK` if any blocking issues exist
* `WARN` if warnings exceed configured thresholds
* `MONITOR` if non-blocking medium risks exist
* `ALLOW` otherwise

## Recommendations

Recommendations are grouped by scan type and action severity:

* `IMMEDIATE_FIX` for `BLOCK` level issues (critical)
* `SCHEDULE_FIX` for `WARN` level issues
  Each includes:
* Priority
* Title & description
* Specific guidance (especially for IDOR)
* Sample affected items
* Estimated effort

## Custom IDOR Rules

Custom Semgrep rules are auto-generated for:

* Direct object access without auth
* Missing authorization checks
* URL parameter manipulation
* File path manipulation
* Unsafe database access patterns
* Session manipulation

## Example Invocation

```python
import asyncio
from enhanced_security_scanner import EnhancedSecurityScanner

async def run():
    scanner = EnhancedSecurityScanner(config_path="config.json")
    results = await scanner.run_security_checks("https://github.com/example/repo.git", branch="main")
    scanner.save_enhanced_report()

asyncio.run(run())
```

## Logging & Errors

* Individual scan modules annotate their `status` (`success`, `skipped`, `error`, `timeout`) and include human-readable error messages.
* Failures in external tools (e.g., missing binaries or timeouts) are surfaced in respective sections.

## Extensibility

* Configuration-driven: add/remove rulesets, adjust thresholds, plug in API keys.
* New scan types can be integrated by following existing pattern: gather raw data, classify risk, update summary/recommendations.

## Testing Recommendations

* Mock external tool outputs to unit test classification logic (`calculate_risk_level`, `classify_sast_risk`, `classify_idor_risk`, etc.).
* Use temporary repositories with known vulnerable patterns to validate end-to-end behavior.

## Contribution

* Follow existing style: explicit risk mapping, clear reasoning strings.
* Add new rules by extending `semgrep_config` or augmenting classification helpers.
* Update the recommendation generator to handle new scan types consistently.

## Limitations / Notes

* External tools must be installed and available in `PATH`; missing tools result in errors in their section.
* CVE enrichment depends on NVD availability and respects rate limiting.
* IDOR rule heuristics are pattern-based and may require tuning for project-specific frameworks.

