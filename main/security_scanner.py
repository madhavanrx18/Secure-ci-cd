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
import requests
import git
from security_models import RiskLevel, Action, CVEInfo, VulnerabilityFinding
import uuid

 

class EnhancedSecurityScanner:
    def __init__(self, config_path: str = None):
        self.config = self.load_config(config_path)
        self.cve_cache = {}  # Cache CVE lookups to avoid API rate limits
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'sca': {},
            'secrets': {},
            'sast': {},
            'sbom': {},
            'summary': {},
            'risk_assessment': {},
            'recommendations': []
        }
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration with enhanced CVE-based thresholds"""
        default_config = {
            'tools': {
                'sca': 'safety',
                'secrets': 'gitleaks',
                'sast': 'bandit'
            },
            'risk_thresholds': {
                # CVE Score based thresholds
                'critical_cvss_min': 9.0,      
                'high_cvss_min': 7.0,          
                'medium_cvss_min': 4.0,        
                'low_cvss_min': 0.1,           
                
                # Action thresholds
                'block_on_critical': True,      
                'block_on_high_count': 5,       
                'warn_on_medium_count': 10,     
                
                # Age-based risk adjustment
                'recent_cve_days': 30,          
                'exploit_multiplier': 1.5,      
                
                # Secrets thresholds
                'secrets_max_findings': 0,      
                
                # SAST thresholds by type
                'sast_critical_types': ['sql_injection', 'code_injection', 'xss'],
                'sast_high_types': ['hardcoded_password', 'weak_crypto'],
            },
            'cve_sources': {
                'nvd_api_key': None,  # Optional NVD API key for higher rate limits
                'use_offline_db': False,  # Use local CVE database if available
            },
            'report_format': 'json'
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config

    async def get_cve_info(self, cve_id: str) -> Optional[CVEInfo]:

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
                # If no requirements file, generate SBOM instead
                try:
                    sbom = self.generate_sbom_from_requirements(repo_path)
                    self.results['sbom'] = sbom
                    components = sbom.get('components', [])
                    # 1) Try Safety against a temporary requirements.txt synthesized from SBOM in repo root
                    tmp_req = None
                    try:
                        repo_req_path = Path(repo_path) / 'requirements.txt'
                        created_repo_req = False
                        if not repo_req_path.exists():
                            created_repo_req = True
                            tmp_req = str(repo_req_path)
                        else:
                            # fallback to a uniquely named temp file inside repo
                            tmp_req = str(Path(repo_path) / f"requirements_sbom_{uuid.uuid4().hex}.txt")
                        with open(tmp_req, 'w') as tf:
                            for comp in components:
                                name = comp.get('name')
                                ver = comp.get('version')
                                if not name:
                                    continue
                                line = name
                                if ver:
                                    line = f"{name}=={ver}"
                                tf.write(line + "\n")
                        result = subprocess.run([
                            'safety', 'check', '--json', '--file', tmp_req
                        ], capture_output=True, text=True, cwd=repo_path)
                        parsed_ok = False
                        if result.stdout:
                            try:
                                vulnerabilities = json.loads(result.stdout)
                                parsed_ok = True
                                sca_results['vulnerabilities'] = vulnerabilities
                                for vuln in vulnerabilities:
                                    cve_id = None
                                    for id_item in vuln.get('ids', []) or []:
                                        if str(id_item).startswith('CVE-'):
                                            cve_id = id_item
                                            break
                                    cve_info = None
                                    if cve_id:
                                        cve_info = await self.get_cve_info(cve_id)
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
                                sca_results['status'] = 'success'
                                sca_results['error'] = None
                            except json.JSONDecodeError:
                                parsed_ok = False
                        if not parsed_ok:
                            raise RuntimeError('Safety parsing failed or empty output')
                    finally:
                        try:
                            if tmp_req and os.path.exists(tmp_req):
                                # Only clean up if we created it; don't delete user's real requirements.txt
                                if 'requirements_sbom_' in Path(tmp_req).name or created_repo_req:
                                    os.remove(tmp_req)
                        except Exception:
                            pass
                    
                except Exception as safety_sbom_err:
                    # 2) Fallback to OSV if Safety path failed
                    try:
                        components = self.results.get('sbom', {}).get('components', [])
                        osv_findings = await self._run_osv_sca_from_sbom(components)
                        for finding in osv_findings:
                            sca_results['findings'].append(finding)
                            risk = finding.get('risk_level') or 'LOW'
                            action = finding.get('action') or 'IGNORE'
                            sca_results['risk_summary'][risk] += 1
                            sca_results['actions'][action] += 1
                        sca_results['tool'] = 'osv'
                        sca_results['status'] = 'success'
                        sca_results['error'] = None
                    except Exception as osv_err:
                        sca_results['status'] = 'skipped'
                        sca_results['error'] = f'No requirements.txt found; Safety-from-SBOM failed: {safety_sbom_err}; OSV fallback failed: {osv_err}'
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

    async def _run_osv_sca_from_sbom(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Query OSV for each PyPI component from SBOM and convert to findings."""
        findings: List[Dict[str, Any]] = []
        if not components:
            return findings
        
        async with aiohttp.ClientSession() as session:
            for comp in components:
                name = comp.get('name')
                version = comp.get('version')
                if not name or not version:
                    continue
                try:
                    payload = {
                        'package': {'ecosystem': 'PyPI', 'name': name},
                        'version': version
                    }
                    async with session.post('https://api.osv.dev/v1/query', json=payload) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                        vulns = data.get('vulns', [])
                        for v in vulns:
                            cve_id = None
                            # prefer CVE id if present
                            for alias in v.get('aliases', []) or []:
                                if str(alias).startswith('CVE-'):
                                    cve_id = alias
                                    break
                            cve_info = None
                            if cve_id:
                                cve_info = await self.get_cve_info(cve_id)
                            # Fallback severity if no CVE info
                            risk_level, action, reasoning = self.calculate_risk_level(cve_info)
                            finding = {
                                'tool': 'osv',
                                'vulnerability_id': cve_id or v.get('id', 'OSV'),
                                'package_name': name,
                                'current_version': version,
                                'fixed_version': None,
                                'cve_info': cve_info.__dict__ if cve_info else None,
                                'risk_level': risk_level.value,
                                'action': action.value,
                                'reasoning': reasoning or 'OSV vulnerability detected'
                            }
                            findings.append(finding)
                except Exception:
                    # Continue with other components
                    continue
        return findings

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
        """Run all enhanced security checks"""
        repo_path = None
        
        try:
            # Clone repository
            repo_path = self.clone_repository(repo_url, branch)
            
            # Generate SBOM from repository (requirements files)
            try:
                self.results['sbom'] = self.generate_sbom_from_requirements(repo_path)
            except Exception as sbom_err:
                # Non-fatal; continue other scans
                self.results['sbom'] = {'status': 'error', 'error': str(sbom_err)}
        
            # Run security checks in parallel (SCA needs async for CVE lookups)
            sca_task = self.run_enhanced_sca_check(repo_path)
            
            with ThreadPoolExecutor(max_workers=2) as executor:
                secrets_future = executor.submit(self.run_enhanced_secrets_check, repo_path)
                sast_future = executor.submit(self.run_enhanced_sast_check, repo_path)
                
                # Wait for async SCA and sync results
                self.results['sca'] = await sca_task
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

    def generate_sbom_from_requirements(self, repo_path: str) -> Dict[str, Any]:
        """Generate a minimal CycloneDX-like SBOM from requirements files.
        This avoids external dependencies by parsing requirements*.txt.
        """
        print("Generating SBOM from requirements files...")
        requirements_files: List[Path] = []
        for root, _, files in os.walk(repo_path):
            for fname in files:
                lower = fname.lower()
                if lower.startswith('requirements') and lower.endswith('.txt'):
                    requirements_files.append(Path(root) / fname)
        
        components: List[Dict[str, Any]] = []
        seen: set = set()
        
        def parse_req_line(line: str) -> Tuple[str, Optional[str]]:
            # Strip comments and options
            line = line.split('#', 1)[0].strip()
            if not line or line.startswith('-'):
                return '', None
            # Common specifiers: ==, >=, <=, ~=, >, <, ===
            for sep in ['===', '==', '>=', '<=', '~=', '>', '<']:
                if sep in line:
                    name, ver = line.split(sep, 1)
                    return name.strip(), ver.strip() or None
            # No version pinned
            return line.strip(), None
        
        for req_file in requirements_files:
            try:
                with open(req_file, 'r') as f:
                    for raw in f:
                        name, ver = parse_req_line(raw)
                        if not name:
                            continue
                        key = (name.lower(), ver or '')
                        if key in seen:
                            continue
                        seen.add(key)
                        purl = None
                        if ver:
                            purl = f"pkg:pypi/{name}@{ver}"
                        else:
                            purl = f"pkg:pypi/{name}"
                        components.append({
                            'type': 'library',
                            'name': name,
                            'version': ver,
                            'purl': purl,
                            'licenses': []
                        })
            except Exception as e:
                # Continue with other files
                print(f"SBOM: failed to read {req_file}: {e}")
                continue
        
        bom: Dict[str, Any] = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'serialNumber': f"urn:uuid:{uuid.uuid4()}",
            'version': 1,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tools': [{'vendor': 'Secure-ci-cd', 'name': 'EnhancedSecurityScanner', 'version': 'internal'}],
                'component': {
                    'type': 'application',
                    'name': Path(repo_path).name
                }
            },
            'components': components,
            'componentCount': len(components),
            'status': 'success' if components else 'empty'
        }
        return bom

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
        """Generate enhanced summary with risk-based decision making"""
        # Aggregate risk summaries
        total_risks = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_actions = {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0}
        
        for check_type in ['sca', 'secrets', 'sast']:
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
            'deployment_recommendation': self.get_deployment_recommendation(overall_decision, total_risks)
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
        """Generate detailed risk assessment"""
        return {
            'assessment_timestamp': datetime.now().isoformat(),
            'methodology': 'CVE-based risk scoring with contextual adjustments',
            'risk_factors': {
                'cve_scores_used': len(self.cve_cache),
                'recent_cves': sum(1 for cve in self.cve_cache.values() 
                                 if self.is_recent_cve(cve)),
                'high_exploitability': sum(1 for cve in self.cve_cache.values() 
                                         if cve.exploitability_score > 8.0)
            }
        }

    def is_recent_cve(self, cve_info: CVEInfo) -> bool:
        """Check if CVE is recently published"""
        try:
            pub_date = datetime.fromisoformat(cve_info.published_date.replace('Z', '+00:00'))
            days_old = (datetime.now().replace(tzinfo=pub_date.tzinfo) - pub_date).days
            return days_old <= self.config['risk_thresholds']['recent_cve_days']
        except:
            return False

    def generate_smart_recommendations(self) -> List[Dict[str, Any]]:
        """Generate intelligent, actionable recommendations"""
        recommendations = []
        
        # Analyze each scan type
        for scan_type in ['sca', 'secrets', 'sast']:
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
                    recommendations.append({
                        'priority': 'CRITICAL',
                        'action': 'IMMEDIATE_FIX',
                        'title': f'Fix {len(items)} critical {scan_type.upper()} issues',
                        'description': f'Deployment blocked due to critical security issues in {scan_type}',
                        'items': items[:5],  # Show top 5
                        'estimated_effort': 'High'
                    })
                elif action == 'WARN':
                    recommendations.append({
                        'priority': 'HIGH',
                        'action': 'SCHEDULE_FIX',
                        'title': f'Address {len(items)} high-risk {scan_type.upper()} issues',
                        'description': f'Schedule fixes for high-risk issues found in {scan_type}',
                        'items': items[:3],
                        'estimated_effort': 'Medium'
                    })
        
        return recommendations

    def save_enhanced_report(self, output_file: str = None):
        """Save enhanced security report with risk assessment"""
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
    """Enhanced security scan with CVE-based risk assessment"""
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
        
        # Enhanced logging
        summary = results['summary']
        print(f"[+] Enhanced security scan completed for {repo_name}")
        print(f"    Overall Decision: {summary['overall_decision']}")
        print(f"    Risk Score: {summary['risk_score']:.1f}/100")
        print(f"    Deployment: {summary['deployment_recommendation']}")
        
        # Print risk breakdown
        risks = summary['total_risks']
        print(f"    Risk Breakdown: Critical({risks['CRITICAL']}) High({risks['HIGH']}) Medium({risks['MEDIUM']}) Low({risks['LOW']})")
        
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
    # Example usage with enhanced scanning
    async def main():
        scanner = EnhancedSecurityScanner()
        
        # Test with a repository
        repo_url = "https://github.com/madhavanrx18/Secure-ci-cd"
        print("🔍 Starting Enhanced Security Scan with CVE Analysis...")
        print("=" * 60)
        
        results = await scanner.run_security_checks(repo_url)
        scanner.save_enhanced_report()
        
        # Print comprehensive summary
        print("\n" + "=" * 60)
        print("📊 ENHANCED SECURITY SCAN RESULTS")
        print("=" * 60)
        
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
        
        # Show scan performance
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment:
            factors = risk_assessment.get('risk_factors', {})
            print(f"\n📋 Scan Statistics:")
            print(f"  CVE lookups performed: {factors.get('cve_scores_used', 0)}")
            print(f"  Recent CVEs found: {factors.get('recent_cves', 0)}")
            print(f"  High exploitability CVEs: {factors.get('high_exploitability', 0)}")
        
        print("\n" + "=" * 60)
        print("✅ Enhanced Security Scan Complete")
        print("=" * 60)
    
    # Uncomment to test
    asyncio.run(main())