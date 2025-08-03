#!/usr/bin/env python3
"""
Enhanced DevSecOps Security Scanner with CVE Scoring and IDOR Detection
Implements SCA, Secrets Scanning, SAST, and IDOR detection using Semgrep
Integrated with existing FastAPI webhook infrastructure
"""

import os
import json
import asyncio
import subprocess
import tempfile
import shutil 
import aiohttp
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
import requests
import git

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Action(Enum):
    BLOCK = "BLOCK"           # Block deployment
    WARN = "WARN"             # Allow but warn
    IGNORE = "IGNORE"         # Ignore finding
    MONITOR = "MONITOR"       # Continue monitoring

@dataclass
class CVEInfo:
    cve_id: str
    cvss_score: float
    cvss_vector: str
    severity: str
    description: str
    published_date: str
    last_modified: str
    references: List[str]
    exploitability_score: float = 0.0
    impact_score: float = 0.0

@dataclass
class VulnerabilityFinding:
    tool: str
    vulnerability_id: str
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    cve_info: Optional[CVEInfo]
    risk_level: RiskLevel
    action: Action
    reasoning: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None

@dataclass
class IDORFinding:
    tool: str
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    code_snippet: str
    message: str
    severity: str
    risk_level: RiskLevel
    action: Action
    reasoning: str
    pattern_type: str  # e.g., "direct_object_access", "missing_authorization", etc.

class EnhancedSecurityScanner:
    def __init__(self, config_path: str = None):
        self.config = self.load_config(config_path)
        self.cve_cache = {}  # Cache CVE lookups to avoid API rate limits
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'sca': {},
            'secrets': {},
            'sast': {},
            'idor': {},  # New IDOR section
            'summary': {},
            'risk_assessment': {},
            'recommendations': []
        }
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration with enhanced CVE-based thresholds and IDOR detection"""
        default_config = {
            'tools': {
                'sca': 'safety',
                'secrets': 'gitleaks',
                'sast': 'bandit',
                'idor': 'semgrep'  # New IDOR tool
            },
            'risk_thresholds': {
                # CVE Score based thresholds
                'critical_cvss_min': 9.0,      # CVSS 9.0+ = CRITICAL
                'high_cvss_min': 7.0,          # CVSS 7.0-8.9 = HIGH
                'medium_cvss_min': 4.0,        # CVSS 4.0-6.9 = MEDIUM
                'low_cvss_min': 0.1,           # CVSS 0.1-3.9 = LOW
                
                # Action thresholds
                'block_on_critical': True,      # Block deployment on CRITICAL
                'block_on_high_count': 5,       # Block if >5 HIGH severity issues
                'warn_on_medium_count': 10,     # Warn if >10 MEDIUM severity issues
                
                # Age-based risk adjustment
                'recent_cve_days': 30,          # CVEs published in last 30 days get +1 risk
                'exploit_multiplier': 1.5,      # Multiply score if exploit exists
                
                # Secrets thresholds
                'secrets_max_findings': 0,      # Zero tolerance for secrets
                
                # SAST thresholds by type
                'sast_critical_types': ['sql_injection', 'code_injection', 'xss'],
                'sast_high_types': ['hardcoded_password', 'weak_crypto'],
                
                # IDOR-specific thresholds
                'idor_critical_patterns': ['direct_database_access', 'missing_auth_check'],
                'idor_high_patterns': ['parameter_manipulation', 'path_traversal'],
                'idor_block_on_critical': True,  # Block deployment on critical IDOR
            },
            'cve_sources': {
                'nvd_api_key': None,  # Optional NVD API key for higher rate limits
                'use_offline_db': False,  # Use local CVE database if available
            },
            'semgrep_config': {
                'rules_path': None,  # Custom rules path, if None uses default rulesets
                'rulesets': [
                    'p/owasp-top-10',  # OWASP Top 10 rules
                    'p/security-audit',  # General security audit rules
                    'p/insecure-transport',  # Transport security
                ],
                'custom_idor_rules': True,  # Enable custom IDOR rules
                'timeout': 300,  # Semgrep timeout in seconds
            },
            'report_format': 'json'
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config

    def create_custom_idor_rules(self, rules_dir: str) -> str:
        """Create custom Semgrep rules for IDOR detection"""
        rules_file = os.path.join(rules_dir, 'idor_rules.yml')
        
        idor_rules = """
rules:
  - id: idor-direct-object-access
    patterns:
      - pattern-either:
          - pattern: |
              def $FUNC(..., $ID, ...):
                ...
                $MODEL.objects.get(id=$ID)
          - pattern: |
              def $FUNC(..., $ID, ...):
                ...
                $MODEL.objects.filter(id=$ID)
          - pattern: |
              @app.route("/<int:$ID>")
              def $FUNC($ID):
                ...
                $MODEL.query.get($ID)
          - pattern: |
              @app.route("/<$ID>")
              def $FUNC($ID):
                ...
                $DB.execute("SELECT * FROM ... WHERE id = %s", $ID)
    message: "Potential IDOR: Direct object access without authorization check"
    severity: ERROR
    languages: [python]
    
  - id: idor-missing-auth-check
    patterns:
      - pattern-either:
          - pattern: |
              def $FUNC(..., $ID, ...):
                ...
                $OBJ = $MODEL.objects.get(id=$ID)
                ...
          - pattern: |
              def $FUNC(...):
                ...
                $ID = request.args.get('id')
                ...
                $OBJ = $MODEL.objects.get(id=$ID)
    pattern-not-inside:
      - pattern-either:
          - pattern: |
              if $OBJ.user_id == current_user.id:
                ...
          - pattern: |
              if $OBJ.owner == current_user:
                ...
          - pattern: |
              @login_required
              def $FUNC(...):
                ...
          - pattern: |
              if not check_permission(...):
                ...
    message: "Potential IDOR: Object access without ownership/permission validation"
    severity: ERROR
    languages: [python]
    
  - id: idor-url-parameter-manipulation
    patterns:
      - pattern-either:
          - pattern: |
              $ID = request.args.get('$PARAM')
              ...
              $MODEL.objects.get(id=$ID)
          - pattern: |
              $ID = request.form.get('$PARAM')
              ...
              $MODEL.objects.get(id=$ID)
          - pattern: |
              $ID = request.json.get('$PARAM')
              ...
              $MODEL.objects.get(id=$ID)
    message: "Potential IDOR: Direct use of user-controlled parameter for object access"
    severity: WARNING
    languages: [python]
    
  - id: idor-file-path-manipulation
    patterns:
      - pattern-either:
          - pattern: |
              $PATH = request.args.get('file')
              ...
              open($PATH, ...)
          - pattern: |
              $PATH = request.args.get('path')
              ...
              with open($PATH, ...) as $F:
                ...
          - pattern: |
              def download_file($FILENAME):
                ...
                return send_file($FILENAME)
    message: "Potential IDOR: File path manipulation vulnerability"
    severity: ERROR
    languages: [python]
    
  - id: idor-database-injection-risk
    patterns:
      - pattern-either:
          - pattern: |
              $QUERY = f"SELECT * FROM ... WHERE id = {$ID}"
              ...
              cursor.execute($QUERY)
          - pattern: |
              $QUERY = "SELECT * FROM ... WHERE id = " + str($ID)
              ...
              cursor.execute($QUERY)
    message: "Potential IDOR with SQL injection risk: Unsafe query construction"
    severity: ERROR
    languages: [python]
    
  - id: idor-api-endpoint-exposure
    patterns:
      - pattern-either:
          - pattern: |
              @app.route("/api/users/<int:$ID>")
              def get_user($ID):
                ...
                return $USER_DATA
          - pattern: |
              @app.route("/api/orders/<int:$ID>")
              def get_order($ID):
                ...
                return $ORDER_DATA
    pattern-not-inside:
      - pattern: |
          if current_user.id != $ID:
            abort(403)
    message: "Potential IDOR: API endpoint exposes user data without authorization"
    severity: WARNING
    languages: [python]

  - id: idor-session-manipulation
    patterns:
      - pattern-either:
          - pattern: |
              $USER_ID = session.get('user_id')
              ...
              if request.method == 'POST':
                $USER_ID = request.form.get('user_id')
          - pattern: |
              $USER_ID = request.json.get('user_id')
              ...
              $USER = User.objects.get(id=$USER_ID)
    message: "Potential IDOR: User ID manipulation in session or request"
    severity: WARNING
    languages: [python]
"""
        
        with open(rules_file, 'w') as f:
            f.write(idor_rules)
        
        return rules_file

    async def run_idor_detection(self, repo_path: str) -> Dict[str, Any]:
        """Run IDOR detection using Semgrep with custom rules"""
        print("Running IDOR Detection using Semgrep...")
        
        idor_results = {
            'tool': self.config['tools']['idor'],
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'rules_used': [],
            'status': 'success',
            'error': None
        }
        
        try:
            # Create temporary directory for custom rules
            rules_dir = tempfile.mkdtemp()
            
            # Prepare Semgrep command
            semgrep_cmd = ['semgrep', '--json', '--quiet']
            
            # Add default rulesets
            for ruleset in self.config['semgrep_config']['rulesets']:
                semgrep_cmd.extend(['--config', ruleset])
                idor_results['rules_used'].append(ruleset)
            
            # Add custom IDOR rules if enabled
            if self.config['semgrep_config']['custom_idor_rules']:
                custom_rules_file = self.create_custom_idor_rules(rules_dir)
                semgrep_cmd.extend(['--config', custom_rules_file])
                idor_results['rules_used'].append('custom_idor_rules')
            
            # Add custom rules path if specified
            if self.config['semgrep_config']['rules_path']:
                semgrep_cmd.extend(['--config', self.config['semgrep_config']['rules_path']])
                idor_results['rules_used'].append('custom_rules_path')
            
            # Add timeout
            semgrep_cmd.extend(['--timeout', str(self.config['semgrep_config']['timeout'])])
            
            # Add target path
            semgrep_cmd.append(repo_path)
            
            # Run Semgrep
            result = subprocess.run(
                semgrep_cmd, 
                capture_output=True, 
                text=True, 
                cwd=repo_path,
                timeout=self.config['semgrep_config']['timeout']
            )
            
            if result.stdout:
                try:
                    semgrep_data = json.loads(result.stdout)
                    findings = semgrep_data.get('results', [])
                    
                    for finding in findings:
                        # Extract finding details
                        rule_id = finding.get('check_id', 'unknown')
                        file_path = finding.get('path', 'unknown')
                        start_line = finding.get('start', {}).get('line', 0)
                        end_line = finding.get('end', {}).get('line', 0)
                        message = finding.get('extra', {}).get('message', 'No message')
                        severity = finding.get('extra', {}).get('severity', 'INFO')
                        
                        # Get code snippet
                        code_snippet = self.extract_code_snippet(
                            os.path.join(repo_path, file_path), 
                            start_line, 
                            end_line
                        )
                        
                        # Classify IDOR risk
                        risk_level, action, reasoning, pattern_type = self.classify_idor_risk(
                            rule_id, severity, message
                        )
                        
                        idor_finding = IDORFinding(
                            tool='semgrep',
                            rule_id=rule_id,
                            rule_name=finding.get('extra', {}).get('metadata', {}).get('owasp', 'Unknown'),
                            file_path=file_path,
                            line_number=start_line,
                            code_snippet=code_snippet,
                            message=message,
                            severity=severity,
                            risk_level=risk_level,
                            action=action,
                            reasoning=reasoning,
                            pattern_type=pattern_type
                        )
                        
                        idor_results['findings'].append(idor_finding.__dict__)
                        idor_results['risk_summary'][risk_level.value] += 1
                        idor_results['actions'][action.value] += 1
                
                except json.JSONDecodeError as e:
                    idor_results['status'] = 'error'
                    idor_results['error'] = f"Failed to parse Semgrep output: {str(e)}"
            
            # Clean up temporary rules directory
            shutil.rmtree(rules_dir, ignore_errors=True)
            
        except subprocess.TimeoutExpired:
            idor_results['status'] = 'timeout'
            idor_results['error'] = f"Semgrep timed out after {self.config['semgrep_config']['timeout']} seconds"
        except FileNotFoundError:
            idor_results['status'] = 'error'
            idor_results['error'] = "Semgrep not found. Please install semgrep: pip install semgrep"
        except Exception as e:
            idor_results['status'] = 'error'
            idor_results['error'] = str(e)
        
        return idor_results

    def extract_code_snippet(self, file_path: str, start_line: int, end_line: int, context_lines: int = 2) -> str:
        """Extract code snippet with context from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Calculate line boundaries with context
            start_idx = max(0, start_line - context_lines - 1)
            end_idx = min(len(lines), end_line + context_lines)
            
            snippet_lines = []
            for i in range(start_idx, end_idx):
                line_num = i + 1
                line_content = lines[i].rstrip()
                
                # Mark the actual finding lines
                if start_line <= line_num <= end_line:
                    snippet_lines.append(f">>> {line_num:4d}: {line_content}")
                else:
                    snippet_lines.append(f"    {line_num:4d}: {line_content}")
            
            return '\n'.join(snippet_lines)
        
        except Exception:
            return "Could not extract code snippet"

    def classify_idor_risk(self, rule_id: str, severity: str, message: str) -> Tuple[RiskLevel, Action, str, str]:
        """Classify IDOR vulnerability risk based on rule ID, severity, and context"""
        rule_id_lower = rule_id.lower()
        message_lower = message.lower()
        
        # Determine pattern type
        if 'direct-object-access' in rule_id_lower or 'direct object access' in message_lower:
            pattern_type = 'direct_object_access'
        elif 'missing-auth' in rule_id_lower or 'authorization' in message_lower:
            pattern_type = 'missing_authorization'
        elif 'parameter-manipulation' in rule_id_lower or 'parameter' in message_lower:
            pattern_type = 'parameter_manipulation'
        elif 'file-path' in rule_id_lower or 'path traversal' in message_lower:
            pattern_type = 'path_traversal'
        elif 'database' in rule_id_lower or 'sql' in message_lower:
            pattern_type = 'database_access'
        elif 'api-endpoint' in rule_id_lower or 'api' in message_lower:
            pattern_type = 'api_exposure'
        elif 'session' in rule_id_lower or 'session' in message_lower:
            pattern_type = 'session_manipulation'
        else:
            pattern_type = 'general_idor'
        
        # Risk classification based on pattern type and severity
        if pattern_type in ['direct_object_access', 'missing_authorization']:
            if severity == 'ERROR':
                return RiskLevel.CRITICAL, Action.BLOCK, f"Critical IDOR: {pattern_type} with {severity} severity", pattern_type
            else:
                return RiskLevel.HIGH, Action.WARN, f"High-risk IDOR: {pattern_type}", pattern_type
        
        elif pattern_type in ['path_traversal', 'database_access']:
            return RiskLevel.CRITICAL, Action.BLOCK, f"Critical security risk: {pattern_type}", pattern_type
        
        elif pattern_type in ['parameter_manipulation', 'api_exposure']:
            if severity == 'ERROR':
                return RiskLevel.HIGH, Action.WARN, f"High-risk IDOR: {pattern_type}", pattern_type
            else:
                return RiskLevel.MEDIUM, Action.MONITOR, f"Medium-risk IDOR: {pattern_type}", pattern_type
        
        elif pattern_type == 'session_manipulation':
            return RiskLevel.MEDIUM, Action.MONITOR, f"Session-based IDOR risk: {pattern_type}", pattern_type
        
        else:
            # General IDOR classification based on severity
            if severity == 'ERROR':
                return RiskLevel.HIGH, Action.WARN, f"General IDOR vulnerability: {severity} severity", pattern_type
            elif severity == 'WARNING':
                return RiskLevel.MEDIUM, Action.MONITOR, f"Potential IDOR vulnerability", pattern_type
            else:
                return RiskLevel.LOW, Action.IGNORE, f"Low-risk IDOR pattern", pattern_type

    async def get_cve_info(self, cve_id: str) -> Optional[CVEInfo]:
        """Fetch CVE information from NVD API with caching"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        try:
            # NVD API v2.0
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}
            
            headers = {}
            if self.config['cve_sources']['nvd_api_key']:
                headers['apiKey'] = self.config['cve_sources']['nvd_api_key']
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('vulnerabilities'):
                            vuln_data = data['vulnerabilities'][0]['cve']
                            
                            # Extract CVSS score
                            cvss_score = 0.0
                            cvss_vector = ""
                            exploitability_score = 0.0
                            impact_score = 0.0
                            
                            # Try CVSS v3.1 first, then v3.0, then v2.0
                            metrics = vuln_data.get('metrics', {})
                            if 'cvssMetricV31' in metrics:
                                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                cvss_score = cvss_data['baseScore']
                                cvss_vector = cvss_data['vectorString']
                                exploitability_score = cvss_data.get('exploitabilityScore', 0.0)
                                impact_score = cvss_data.get('impactScore', 0.0)
                            elif 'cvssMetricV30' in metrics:
                                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                                cvss_score = cvss_data['baseScore']
                                cvss_vector = cvss_data['vectorString']
                            elif 'cvssMetricV2' in metrics:
                                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                                cvss_score = cvss_data['baseScore']
                                cvss_vector = cvss_data['vectorString']
                            
                            # Determine severity based on score
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                            
                            # Extract references
                            references = []
                            for ref in vuln_data.get('references', []):
                                references.append(ref['url'])
                            
                            cve_info = CVEInfo(
                                cve_id=cve_id,
                                cvss_score=cvss_score,
                                cvss_vector=cvss_vector,
                                severity=severity,
                                description=vuln_data['descriptions'][0]['value'],
                                published_date=vuln_data['published'],
                                last_modified=vuln_data['lastModified'],
                                references=references,
                                exploitability_score=exploitability_score,
                                impact_score=impact_score
                            )
                            
                            self.cve_cache[cve_id] = cve_info
                            return cve_info
                    
                    # Rate limiting - wait if needed
                    elif response.status == 429:
                        await asyncio.sleep(1)
                        
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
        
        return None

    def calculate_risk_level(self, cve_info: Optional[CVEInfo], context: Dict = None) -> Tuple[RiskLevel, Action, str]:
        """Calculate risk level and recommended action based on CVE info and context"""
        if not cve_info:
            return RiskLevel.LOW, Action.IGNORE, "No CVE information available"
        
        score = cve_info.cvss_score
        reasoning_parts = [f"CVSS Score: {score}"]
        
        # Age-based risk adjustment
        if cve_info.published_date:
            try:
                pub_date = datetime.fromisoformat(cve_info.published_date.replace('Z', '+00:00'))
                days_old = (datetime.now().replace(tzinfo=pub_date.tzinfo) - pub_date).days
                
                if days_old <= self.config['risk_thresholds']['recent_cve_days']:
                    score += 1.0  # Increase risk for recent CVEs
                    reasoning_parts.append(f"Recent CVE (published {days_old} days ago)")
            except:
                pass
        
        # Exploitability adjustment
        if cve_info.exploitability_score > 8.0:
            score *= self.config['risk_thresholds']['exploit_multiplier']
            reasoning_parts.append("High exploitability score")
        
        # Context-based adjustments
        if context:
            # Production environment gets higher risk
            if context.get('environment') == 'production':
                score += 0.5
                reasoning_parts.append("Production environment")
            
            # Internet-facing services get higher risk
            if context.get('internet_facing', False):
                score += 0.5
                reasoning_parts.append("Internet-facing service")
        
        # Determine risk level and action
        if score >= self.config['risk_thresholds']['critical_cvss_min']:
            risk_level = RiskLevel.CRITICAL
            action = Action.BLOCK if self.config['risk_thresholds']['block_on_critical'] else Action.WARN
        elif score >= self.config['risk_thresholds']['high_cvss_min']:
            risk_level = RiskLevel.HIGH
            action = Action.WARN
        elif score >= self.config['risk_thresholds']['medium_cvss_min']:
            risk_level = RiskLevel.MEDIUM
            action = Action.MONITOR
        else:
            risk_level = RiskLevel.LOW
            action = Action.IGNORE
        
        reasoning = "; ".join(reasoning_parts)
        return risk_level, action, reasoning

    async def run_enhanced_sca_check(self, repo_path: str) -> Dict[str, Any]:
        """Enhanced SCA with CVE scoring"""
        print("Running Enhanced SCA (Software Composition Analysis) with CVE scoring...")
        
        sca_results = {
            'tool': self.config['tools']['sca'],
            'vulnerabilities': [],
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'status': 'success',
            'error': None
        }
        
        try:
            # Find requirements files
            req_files = list(Path(repo_path).rglob('requirements*.txt'))
            if not req_files:
                sca_results['status'] = 'skipped'
                sca_results['error'] = 'No requirements.txt found'
                return sca_results
            
            # Run safety check
            result = subprocess.run([
                'safety', 'check', '--json', '--file', str(req_files[0])
            ], capture_output=True, text=True, cwd=repo_path)
            
            if result.returncode != 0 and result.stdout:
                try:
                    vulnerabilities = json.loads(result.stdout)
                    sca_results['vulnerabilities'] = vulnerabilities
                    
                    # Process each vulnerability with CVE scoring
                    for vuln in vulnerabilities:
                        # Extract CVE ID if available
                        cve_id = None
                        for id_item in vuln.get('ids', []):
                            if id_item.startswith('CVE-'):
                                cve_id = id_item
                                break
                        
                        # Get CVE information
                        cve_info = None
                        if cve_id:
                            cve_info = await self.get_cve_info(cve_id)
                        
                        # Calculate risk
                        risk_level, action, reasoning = self.calculate_risk_level(cve_info)
                        
                        finding = VulnerabilityFinding(
                            tool='safety',
                            vulnerability_id=cve_id or vuln.get('id', 'Unknown'),
                            package_name=vuln.get('package', 'Unknown'),
                            current_version=vuln.get('installed_version', 'Unknown'),
                            fixed_version=vuln.get('fixed_in', None),
                            cve_info=cve_info,
                            risk_level=risk_level,
                            action=action,
                            reasoning=reasoning
                        )
                        
                        sca_results['findings'].append(finding.__dict__)
                        sca_results['risk_summary'][risk_level.value] += 1
                        sca_results['actions'][action.value] += 1
                        
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            sca_results['status'] = 'error'
            sca_results['error'] = str(e)
        
        return sca_results

    def run_enhanced_secrets_check(self, repo_path: str) -> Dict[str, Any]:
        """Enhanced secrets scanning with risk assessment"""
        print("Running Enhanced Secrets Scanning...")
        
        secrets_results = {
            'tool': self.config['tools']['secrets'],
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'status': 'success',
            'error': None
        }
        
        try:
            # Run gitleaks
            result = subprocess.run([
                'gitleaks', 'detect', '--source', repo_path, '--report-format', 'json'
            ], capture_output=True, text=True)
            
            if result.returncode != 0 and result.stdout:
                try:
                    findings = json.loads(result.stdout)
                    if not isinstance(findings, list):
                        findings = [findings]
                    
                    for finding in findings:
                        # Classify secret type and determine risk
                        secret_type = finding.get('RuleID', 'unknown')
                        risk_level, action = self.classify_secret_risk(secret_type, finding)
                        
                        enhanced_finding = {
                            'tool': 'gitleaks',
                            'secret_type': secret_type,
                            'file_path': finding.get('File', 'Unknown'),
                            'line_number': finding.get('StartLine', 0),
                            'risk_level': risk_level.value,
                            'action': action.value,
                            'reasoning': f"Secret type: {secret_type}",
                            'commit': finding.get('Commit', ''),
                            'description': finding.get('Description', '')
                        }
                        
                        secrets_results['findings'].append(enhanced_finding)
                        secrets_results['risk_summary'][risk_level.value] += 1
                        secrets_results['actions'][action.value] += 1
                        
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            secrets_results['status'] = 'error'
            secrets_results['error'] = str(e)
        
        return secrets_results

    def classify_secret_risk(self, secret_type: str, finding: Dict) -> Tuple[RiskLevel, Action]:
        """Classify secret risk based on type and context"""
        high_risk_secrets = [
            'aws-access-token', 'gcp-service-account', 'azure-storage-account-key',
            'private-key', 'jwt', 'database-password', 'api-key'
        ]
        
        medium_risk_secrets = [
            'github-pat', 'slack-token', 'discord-token'
        ]
        
        if any(risk_type in secret_type.lower() for risk_type in high_risk_secrets):
            return RiskLevel.CRITICAL, Action.BLOCK
        elif any(risk_type in secret_type.lower() for risk_type in medium_risk_secrets):
            return RiskLevel.HIGH, Action.WARN
        else:
            return RiskLevel.MEDIUM, Action.MONITOR

    def run_enhanced_sast_check(self, repo_path: str) -> Dict[str, Any]:
        """Enhanced SAST with risk-based classification"""
        print("Running Enhanced SAST (Static Application Security Testing)...")
        
        sast_results = {
            'tool': self.config['tools']['sast'],
            'issues': [],
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'status': 'success',
            'error': None
        }
        
        try:
            # Run bandit for Python files
            result = subprocess.run([
                'bandit', '-r', repo_path, '-f', 'json'
            ], capture_output=True, text=True)
            
            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    issues = bandit_data.get('results', [])
                    sast_results['issues'] = issues
                    
                    for issue in issues:
                        # Enhanced risk classification
                        risk_level, action = self.classify_sast_risk(issue)
                        
                        enhanced_finding = {
                            'tool': 'bandit',
                            'test_id': issue.get('test_id', 'Unknown'),
                            'test_name': issue.get('test_name', 'Unknown'),
                            'file_path': issue.get('filename', 'Unknown'),
                            'line_number': issue.get('line_number', 0),
                            'issue_severity': issue.get('issue_severity', 'UNKNOWN'),
                            'issue_confidence': issue.get('issue_confidence', 'UNKNOWN'),
                            'risk_level': risk_level.value,
                            'action': action.value,
                            'reasoning': f"Bandit severity: {issue.get('issue_severity')}, confidence: {issue.get('issue_confidence')}",
                            'description': issue.get('issue_text', ''),
                            'code': issue.get('code', '')
                        }
                        
                        sast_results['findings'].append(enhanced_finding)
                        sast_results['risk_summary'][risk_level.value] += 1
                        sast_results['actions'][action.value] += 1
                        
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            sast_results['status'] = 'error'
            sast_results['error'] = str(e)
        
        return sast_results

    def classify_sast_risk(self, issue: Dict) -> Tuple[RiskLevel, Action]:
        """Classify SAST issue risk based on severity, confidence, and type"""
        severity = issue.get('issue_severity', 'LOW')
        confidence = issue.get('issue_confidence', 'LOW')
        test_name = issue.get('test_name', '').lower()
        
        # Critical issues that should block deployment
        critical_patterns = ['sql_injection', 'code_injection', 'exec_used']
        if any(pattern in test_name for pattern in critical_patterns):
            return RiskLevel.CRITICAL, Action.BLOCK
        
        # High severity with high confidence
        if severity == 'HIGH' and confidence == 'HIGH':
            return RiskLevel.HIGH, Action.WARN
        elif severity == 'HIGH':
            return RiskLevel.MEDIUM, Action.MONITOR
        elif severity == 'MEDIUM' and confidence == 'HIGH':
            return RiskLevel.MEDIUM, Action.MONITOR
        else:
            return RiskLevel.LOW, Action.IGNORE

    async def run_security_checks(self, repo_url: str, branch: str = 'main') -> Dict[str, Any]:
        """Run all enhanced security checks including IDOR detection"""
        repo_path = None
        
        try:
            # Clone repository
            repo_path = self.clone_repository(repo_url, branch)
            
            # Run security checks in parallel
            sca_task = self.run_enhanced_sca_check(repo_path)
            idor_task = self.run_idor_detection(repo_path)  # New IDOR check
            
            with ThreadPoolExecutor(max_workers=2) as executor:
                secrets_future = executor.submit(self.run_enhanced_secrets_check, repo_path)
                sast_future = executor.submit(self.run_enhanced_sast_check, repo_path)
                
                # Wait for async tasks and sync results
                self.results['sca'] = await sca_task
                self.results['idor'] = await idor_task  # New IDOR results
                self.results['secrets'] = secrets_future.result()
                self.results['sast'] = sast_future.result()
            
            # Generate enhanced summary and recommendations
            self.results['summary'] = self.generate_enhanced_summary()
            self.results['risk_assessment'] = self.generate_risk_assessment()
            self.results['recommendations'] = self.generate_smart_recommendations()
            
            return self.results
        
        finally:
            # Cleanup
            if repo_path and os.path.exists(repo_path):
                shutil.rmtree(repo_path, ignore_errors=True)

    def clone_repository(self, repo_url: str, branch: str = 'main') -> str:
        """Clone repository to temporary directory"""
        temp_dir = tempfile.mkdtemp()
        try:
            print(f"Cloning repository: {repo_url}")
            git.Repo.clone_from(repo_url, temp_dir, branch=branch)
            return temp_dir
        except Exception as e:
            print(f"Error cloning repository: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    def generate_enhanced_summary(self) -> Dict[str, Any]:
        """Generate enhanced summary with risk-based decision making including IDOR"""
        # Aggregate risk summaries
        total_risks = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_actions = {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0}
        
        for check_type in ['sca', 'secrets', 'sast', 'idor']:  # Added IDOR
            check_results = self.results[check_type]
            risk_summary = check_results.get('risk_summary', {})
            actions = check_results.get('actions', {})
            
            for risk_level, count in risk_summary.items():
                total_risks[risk_level] += count
            
            for action, count in actions.items():
                total_actions[action] += count
        
        # Determine overall deployment decision
        overall_decision = "ALLOW"
        if total_actions['BLOCK'] > 0:
            overall_decision = "BLOCK"
        elif total_actions['WARN'] > self.config['risk_thresholds'].get('warn_threshold', 3):
            overall_decision = "WARN"
        elif total_actions['MONITOR'] > 0:
            overall_decision = "MONITOR"
        
        return {
            'total_risks': total_risks,
            'total_actions': total_actions,
            'overall_decision': overall_decision,
            'risk_score': self.calculate_overall_risk_score(total_risks),
            'deployment_recommendation': self.get_deployment_recommendation(overall_decision, total_risks),
            'idor_specific': {
                'findings_count': len(self.results['idor'].get('findings', [])),
                'critical_idor': self.results['idor'].get('risk_summary', {}).get('CRITICAL', 0),
                'high_idor': self.results['idor'].get('risk_summary', {}).get('HIGH', 0)
            }
        }

    def calculate_overall_risk_score(self, risks: Dict[str, int]) -> float:
        """Calculate weighted risk score"""
        weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        total_score = sum(risks[level] * weights[level] for level in risks)
        max_possible = sum(risks.values()) * weights['CRITICAL']
        return (total_score / max_possible * 100) if max_possible > 0 else 0

    def get_deployment_recommendation(self, decision: str, risks: Dict[str, int]) -> str:
        """Get human-readable deployment recommendation"""
        if decision == "BLOCK":
            return f"❌ BLOCK DEPLOYMENT: {risks['CRITICAL']} critical vulnerabilities found"
        elif decision == "WARN":
            return f"⚠️  PROCEED WITH CAUTION: {risks['HIGH']} high-risk issues found"
        elif decision == "MONITOR":
            return f"📊 DEPLOY WITH MONITORING: {risks['MEDIUM']} medium-risk issues to monitor"
        else:
            return "✅ SAFE TO DEPLOY: No significant security risks detected"

    def generate_risk_assessment(self) -> Dict[str, Any]:
        """Generate detailed risk assessment including IDOR analysis"""
        return {
            'assessment_timestamp': datetime.now().isoformat(),
            'methodology': 'CVE-based risk scoring with contextual adjustments and IDOR pattern analysis',
            'risk_factors': {
                'cve_scores_used': len(self.cve_cache),
                'recent_cves': sum(1 for cve in self.cve_cache.values() 
                                 if self.is_recent_cve(cve)),
                'high_exploitability': sum(1 for cve in self.cve_cache.values() 
                                         if cve.exploitability_score > 8.0)
            },
            'idor_analysis': {
                'total_patterns_detected': len(self.results['idor'].get('findings', [])),
                'pattern_breakdown': self.analyze_idor_patterns(),
                'high_risk_files': self.get_high_risk_idor_files()
            }
        }

    def analyze_idor_patterns(self) -> Dict[str, int]:
        """Analyze IDOR patterns found"""
        pattern_counts = {}
        for finding in self.results['idor'].get('findings', []):
            pattern_type = finding.get('pattern_type', 'unknown')
            pattern_counts[pattern_type] = pattern_counts.get(pattern_type, 0) + 1
        return pattern_counts

    def get_high_risk_idor_files(self) -> List[str]:
        """Get files with high-risk IDOR vulnerabilities"""
        high_risk_files = []
        for finding in self.results['idor'].get('findings', []):
            if finding.get('risk_level') in ['CRITICAL', 'HIGH']:
                file_path = finding.get('file_path')
                if file_path and file_path not in high_risk_files:
                    high_risk_files.append(file_path)
        return high_risk_files

    def is_recent_cve(self, cve_info: CVEInfo) -> bool:
        """Check if CVE is recently published"""
        try:
            pub_date = datetime.fromisoformat(cve_info.published_date.replace('Z', '+00:00'))
            days_old = (datetime.now().replace(tzinfo=pub_date.tzinfo) - pub_date).days
            return days_old <= self.config['risk_thresholds']['recent_cve_days']
        except:
            return False

    def generate_smart_recommendations(self) -> List[Dict[str, Any]]:
        """Generate intelligent, actionable recommendations including IDOR fixes"""
        recommendations = []
        
        # Analyze each scan type
        for scan_type in ['sca', 'secrets', 'sast', 'idor']:  # Added IDOR
            scan_results = self.results[scan_type]
            findings = scan_results.get('findings', [])
            
            # Group by action required
            actions_needed = {}
            for finding in findings:
                action = finding.get('action', 'IGNORE')
                if action not in actions_needed:
                    actions_needed[action] = []
                actions_needed[action].append(finding)
            
            # Generate recommendations for each action type
            for action, items in actions_needed.items():
                if action == 'BLOCK':
                    if scan_type == 'idor':
                        recommendations.append({
                            'priority': 'CRITICAL',
                            'action': 'IMMEDIATE_FIX',
                            'title': f'Fix {len(items)} critical IDOR vulnerabilities',
                            'description': 'IDOR vulnerabilities can lead to unauthorized data access and privilege escalation',
                            'specific_guidance': self.get_idor_fix_guidance(items),
                            'items': items[:5],
                            'estimated_effort': 'High'
                        })
                    else:
                        recommendations.append({
                            'priority': 'CRITICAL',
                            'action': 'IMMEDIATE_FIX',
                            'title': f'Fix {len(items)} critical {scan_type.upper()} issues',
                            'description': f'Deployment blocked due to critical security issues in {scan_type}',
                            'items': items[:5],
                            'estimated_effort': 'High'
                        })
                elif action == 'WARN':
                    if scan_type == 'idor':
                        recommendations.append({
                            'priority': 'HIGH',
                            'action': 'SCHEDULE_FIX',
                            'title': f'Address {len(items)} high-risk IDOR issues',
                            'description': 'High-risk IDOR patterns that could lead to data breaches',
                            'specific_guidance': self.get_idor_fix_guidance(items),
                            'items': items[:3],
                            'estimated_effort': 'Medium'
                        })
                    else:
                        recommendations.append({
                            'priority': 'HIGH',
                            'action': 'SCHEDULE_FIX',
                            'title': f'Address {len(items)} high-risk {scan_type.upper()} issues',
                            'description': f'Schedule fixes for high-risk issues found in {scan_type}',
                            'items': items[:3],
                            'estimated_effort': 'Medium'
                        })
        
        return recommendations

    def get_idor_fix_guidance(self, idor_findings: List[Dict]) -> List[str]:
        """Generate specific guidance for fixing IDOR vulnerabilities"""
        guidance = []
        pattern_types = set()
        
        for finding in idor_findings:
            pattern_types.add(finding.get('pattern_type', 'unknown'))
        
        if 'direct_object_access' in pattern_types:
            guidance.append("Implement proper authorization checks before accessing objects by ID")
            guidance.append("Verify that the current user has permission to access the requested resource")
        
        if 'missing_authorization' in pattern_types:
            guidance.append("Add ownership validation: check if object.user_id == current_user.id")
            guidance.append("Implement role-based access control (RBAC) for sensitive operations")
        
        if 'parameter_manipulation' in pattern_types:
            guidance.append("Validate and sanitize all user input parameters")
            guidance.append("Use indirect object references (e.g., UUIDs) instead of sequential IDs")
        
        if 'path_traversal' in pattern_types:
            guidance.append("Implement strict file path validation and sanitization")
            guidance.append("Use whitelist-based file access controls")
        
        if 'database_access' in pattern_types:
            guidance.append("Use parameterized queries to prevent SQL injection")
            guidance.append("Implement database-level access controls")
        
        if 'api_exposure' in pattern_types:
            guidance.append("Add authentication and authorization middleware to API endpoints")
            guidance.append("Implement rate limiting and API access controls")
        
        if 'session_manipulation' in pattern_types:
            guidance.append("Never trust user-provided session data for authorization")
            guidance.append("Use server-side session validation")
        
        return guidance

    def save_enhanced_report(self, output_file: str = None):
        """Save enhanced security report with risk assessment and IDOR findings"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"enhanced_security_report_{timestamp}.json"
        
        # Convert any dataclass objects to dict for JSON serialization
        report_data = json.loads(json.dumps(self.results, default=str))
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"Enhanced security report saved to: {output_file}")


# Integration function for webhook handler
async def trigger_enhanced_security_scan(repo_name: str, branch: str, commit_id: str, 
                                       clone_url: str = None, context: Dict = None) -> Dict[str, Any]:
    """Enhanced security scan with CVE-based risk assessment and IDOR detection"""
    print(f"[+] Starting enhanced security scan for {repo_name}:{branch} @ {commit_id}")
    
    if not clone_url:
        clone_url = f"https://github.com/{repo_name}.git"
    
    scanner = EnhancedSecurityScanner()
    
    try:
        results = await scanner.run_security_checks(clone_url, branch)
        
        # Add metadata
        results['metadata'] = {
            'repository': repo_name,
            'branch': branch,
            'commit_id': commit_id,
            'scan_trigger': 'webhook_push',
            'context': context or {}
        }
        
        # Save enhanced report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        repo_safe_name = repo_name.replace('/', '_')
        report_filename = f"enhanced_security_report_{repo_safe_name}_{branch}_{timestamp}.json"
        scanner.save_enhanced_report(report_filename)
        
        # Enhanced logging with IDOR details
        summary = results['summary']
        print(f"[+] Enhanced security scan completed for {repo_name}")
        print(f"    Overall Decision: {summary['overall_decision']}")
        print(f"    Risk Score: {summary['risk_score']:.1f}/100")
        print(f"    Deployment: {summary['deployment_recommendation']}")
        
        # Print risk breakdown
        risks = summary['total_risks']
        print(f"    Risk Breakdown: Critical({risks['CRITICAL']}) High({risks['HIGH']}) Medium({risks['MEDIUM']}) Low({risks['LOW']})")
        
        # Print IDOR-specific details
        idor_info = summary['idor_specific']
        if idor_info['findings_count'] > 0:
            print(f"    IDOR Findings: {idor_info['findings_count']} total, {idor_info['critical_idor']} critical, {idor_info['high_idor']} high")
        
        # Print actionable recommendations
        if results['recommendations']:
            print(f"[!] Recommendations:")
            for rec in results['recommendations'][:3]:  # Show top 3
                print(f"    {rec['priority']}: {rec['title']}")
        
        return results
        
    except Exception as e:
        error_msg = f"Enhanced security scan failed for {repo_name}: {str(e)}"
        print(f"[-] {error_msg}")
        return {
            'error': error_msg,
            'metadata': {
                'repository': repo_name,
                'branch': branch,
                'commit_id': commit_id,
                'scan_trigger': 'webhook_push'
            }
        }


if __name__ == "__main__":
    # Example usage with enhanced scanning including IDOR detection
    async def main():
        scanner = EnhancedSecurityScanner()
        
        # Test with a repository
        repo_url = "https://github.com/madhavanrx18/Secure-ci-cd.git"
        
        print("🔍 Starting Enhanced Security Scan with CVE Analysis and IDOR Detection...")
        print("=" * 80)
        
        results = await scanner.run_security_checks(repo_url)
        scanner.save_enhanced_report()
        
        # Print comprehensive summary
        print("\n" + "=" * 80)
        print("📊 ENHANCED SECURITY SCAN RESULTS")
        print("=" * 80)
        
        summary = results['summary']
        print(f"Overall Decision: {summary['overall_decision']}")
        print(f"Risk Score: {summary['risk_score']:.1f}/100")
        print(f"Deployment Recommendation: {summary['deployment_recommendation']}")
        
        print(f"\n📈 Risk Breakdown:")
        risks = summary['total_risks']
        for level, count in risks.items():
            if count > 0:
                print(f"  {level}: {count} issues")
        
        print(f"\n⚡ Actions Required:")
        actions = summary['total_actions']
        for action, count in actions.items():
            if count > 0:
                print(f"  {action}: {count} items")
        
        # Show IDOR-specific results
        idor_results = results['idor']
        if idor_results.get('findings'):
            print(f"\n🔐 IDOR Detection Results:")
            print(f"  Total IDOR findings: {len(idor_results['findings'])}")
            print(f"  Rules used: {', '.join(idor_results.get('rules_used', []))}")
            
            # Show pattern breakdown
            risk_assessment = results.get('risk_assessment', {})
            idor_analysis = risk_assessment.get('idor_analysis', {})
            pattern_breakdown = idor_analysis.get('pattern_breakdown', {})
            
            if pattern_breakdown:
                print(f"  Pattern breakdown:")
                for pattern, count in pattern_breakdown.items():
                    print(f"    - {pattern}: {count}")
            
            # Show high-risk files
            high_risk_files = idor_analysis.get('high_risk_files', [])
            if high_risk_files:
                print(f"  High-risk files:")
                for file_path in high_risk_files[:5]:  # Show top 5
                    print(f"    - {file_path}")
        
        # Show CVE details if available
        if scanner.cve_cache:
            print(f"\n🔗 CVE Analysis:")
            print(f"  Total CVEs analyzed: {len(scanner.cve_cache)}")
            critical_cves = [cve for cve in scanner.cve_cache.values() if cve.cvss_score >= 9.0]
            high_cves = [cve for cve in scanner.cve_cache.values() if 7.0 <= cve.cvss_score < 9.0]
            
            if critical_cves:
                print(f"  Critical CVEs (CVSS ≥ 9.0): {len(critical_cves)}")
                for cve in critical_cves[:3]:  # Show top 3
                    print(f"    - {cve.cve_id}: CVSS {cve.cvss_score} ({cve.severity})")
            
            if high_cves:
                print(f"  High CVEs (CVSS 7.0-8.9): {len(high_cves)}")
        
        # Show top recommendations
        if results['recommendations']:
            print(f"\n💡 Priority Recommendations:")
            for i, rec in enumerate(results['recommendations'][:5], 1):
                print(f"  {i}. [{rec['priority']}] {rec['title']}")
                print(f"     {rec['description']}")
                print(f"     Effort: {rec['estimated_effort']}")
                
                # Show IDOR-specific guidance
                if 'specific_guidance' in rec:
                    print(f"     Guidance:")
                    for guidance in rec['specific_guidance'][:3]:  # Show top 3
                        print(f"       • {guidance}")
        
        # Show scan performance
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment:
            factors = risk_assessment.get('risk_factors', {})
            print(f"\n📋 Scan Statistics:")
            print(f"  CVE lookups performed: {factors.get('cve_scores_used', 0)}")
            print(f"  Recent CVEs found: {factors.get('recent_cves', 0)}")
            print(f"  High exploitability CVEs: {factors.get('high_exploitability', 0)}")
            
            idor_analysis = risk_assessment.get('idor_analysis', {})
            if idor_analysis:
                print(f"  IDOR patterns detected: {idor_analysis.get('total_patterns_detected', 0)}")
        
        print("\n" + "=" * 80)
        print("✅ Enhanced Security Scan with IDOR Detection Complete")
        print("=" * 80)
    
    # Uncomment to test
    asyncio.run(main())