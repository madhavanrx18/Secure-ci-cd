#!/usr/bin/env python3
"""
DevSecOps Security Scanner
Implements SCA, Secrets Scanning, and SAST checks
Integrated with existing FastAPI webhook infrastructure
"""

import os
import json
import asyncio
import subprocess
import tempfile
import shutil 
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor
import requests
import git

class SecurityScanner:
    def __init__(self, config_path: str = None):
        self.config = self.load_config(config_path)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'sca': {},
            'secrets': {},
            'sast': {},
            'summary': {}
        }
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration or use defaults"""
        default_config = {
            'tools': {
                'sca': 'safety',  # or 'pip-audit'
                'secrets': 'gitleaks',  # or 'truffleHog', 'detect-secrets'
                'sast': 'bandit'  # or 'semgrep'
            },
            'thresholds': {
                'sca_max_vulnerabilities': 0,
                'secrets_max_findings': 0,
                'sast_max_high_severity': 0
            },
            'report_format': 'json'
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config

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

    def run_sca_check(self, repo_path: str) -> Dict[str, Any]:
        """Software Composition Analysis - Check for vulnerable dependencies"""
        print("Running SCA (Software Composition Analysis)...")
        
        sca_results = {
            'tool': self.config['tools']['sca'],
            'vulnerabilities': [],
            'status': 'success',
            'error': None
        }
        
        try:
            if self.config['tools']['sca'] == 'safety':
                # Check if requirements.txt exists
                req_files = list(Path(repo_path).rglob('requirements*.txt'))
                if not req_files:
                    sca_results['status'] = 'skipped'
                    sca_results['error'] = 'No requirements.txt found'
                    return sca_results
                
                # Run safety check
                result = subprocess.run([
                    'safety', 'check', '--json', '--file', str(req_files[0])
                ], capture_output=True, text=True, cwd=repo_path)
                
                if result.returncode == 0:
                    sca_results['vulnerabilities'] = []
                else:
                    try:
                        vulnerabilities = json.loads(result.stdout)
                        sca_results['vulnerabilities'] = vulnerabilities
                    except json.JSONDecodeError:
                        sca_results['vulnerabilities'] = []
            
            elif self.config['tools']['sca'] == 'pip-audit':
                # Run pip-audit
                result = subprocess.run([
                    'pip-audit', '--format=json', '--requirement', 'requirements.txt'
                ], capture_output=True, text=True, cwd=repo_path)
                
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        sca_results['vulnerabilities'] = audit_data.get('vulnerabilities', [])
                    except json.JSONDecodeError:
                        sca_results['vulnerabilities'] = []
        
        except Exception as e:
            sca_results['status'] = 'error'
            sca_results['error'] = str(e)
        
        return sca_results

    def run_secrets_check(self, repo_path: str) -> Dict[str, Any]:
        """Secrets Scanning - Check for exposed secrets"""
        print("Running Secrets Scanning...")
        
        secrets_results = {
            'tool': self.config['tools']['secrets'],
            'findings': [],
            'status': 'success',
            'error': None
        }
        
        try:
            if self.config['tools']['secrets'] == 'gitleaks':
                # Run gitleaks
                result = subprocess.run([
                    'gitleaks', 'detect', '--source', repo_path, '--report-format', 'json'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    secrets_results['findings'] = []
                else:
                    try:
                        if result.stdout:
                            findings = json.loads(result.stdout)
                            secrets_results['findings'] = findings if isinstance(findings, list) else [findings]
                    except json.JSONDecodeError:
                        secrets_results['findings'] = []
            
            elif self.config['tools']['secrets'] == 'detect-secrets':
                # Run detect-secrets
                result = subprocess.run([
                    'detect-secrets', 'scan', '--all-files', repo_path
                ], capture_output=True, text=True)
                
                if result.stdout:
                    try:
                        scan_data = json.loads(result.stdout)
                        findings = []
                        for file_path, secrets in scan_data.get('results', {}).items():
                            for secret in secrets:
                                findings.append({
                                    'file': file_path,
                                    'type': secret.get('type'),
                                    'line': secret.get('line_number')
                                })
                        secrets_results['findings'] = findings
                    except json.JSONDecodeError:
                        secrets_results['findings'] = []
        
        except Exception as e:
            secrets_results['status'] = 'error'
            secrets_results['error'] = str(e)
        
        return secrets_results

    def run_sast_check(self, repo_path: str) -> Dict[str, Any]:
        """Static Application Security Testing"""
        print("Running SAST (Static Application Security Testing)...")
        
        sast_results = {
            'tool': self.config['tools']['sast'],
            'issues': [],
            'status': 'success',
            'error': None
        }
        
        try:
            if self.config['tools']['sast'] == 'bandit':
                # Run bandit for Python files
                result = subprocess.run([
                    'bandit', '-r', repo_path, '-f', 'json'
                ], capture_output=True, text=True)
                
                if result.stdout:
                    try:
                        bandit_data = json.loads(result.stdout)
                        sast_results['issues'] = bandit_data.get('results', [])
                    except json.JSONDecodeError:
                        sast_results['issues'] = []
            
            elif self.config['tools']['sast'] == 'semgrep':
                # Run semgrep
                result = subprocess.run([
                    'semgrep', '--config=auto', '--json', repo_path
                ], capture_output=True, text=True)
                
                if result.stdout:
                    try:
                        semgrep_data = json.loads(result.stdout)
                        sast_results['issues'] = semgrep_data.get('results', [])
                    except json.JSONDecodeError:
                        sast_results['issues'] = []
        
        except Exception as e:
            sast_results['status'] = 'error'
            sast_results['error'] = str(e)
        
        return sast_results

    async def run_security_checks(self, repo_url: str, branch: str = 'main') -> Dict[str, Any]:
        """Run all security checks in parallel"""
        repo_path = None
        
        try:
            # Clone repository
            repo_path = self.clone_repository(repo_url, branch)
            
            # Run security checks in parallel
            with ThreadPoolExecutor(max_workers=3) as executor:
                # Submit all tasks
                sca_future = executor.submit(self.run_sca_check, repo_path)
                secrets_future = executor.submit(self.run_secrets_check, repo_path)
                sast_future = executor.submit(self.run_sast_check, repo_path)
                
                # Wait for results
                self.results['sca'] = sca_future.result()
                self.results['secrets'] = secrets_future.result()
                self.results['sast'] = sast_future.result()
            
            # Generate summary
            self.results['summary'] = self.generate_summary()
            
            return self.results
        
        finally:
            # Cleanup temporary directory
            if repo_path and os.path.exists(repo_path):
                shutil.rmtree(repo_path, ignore_errors=True)

    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary of all security checks"""
        summary = {
            'total_vulnerabilities': len(self.results['sca'].get('vulnerabilities', [])),
            'total_secrets': len(self.results['secrets'].get('findings', [])),
            'total_sast_issues': len(self.results['sast'].get('issues', [])),
            'overall_status': 'pass',
            'recommendations': []
        }
        
        # Check against thresholds
        if summary['total_vulnerabilities'] > self.config['thresholds']['sca_max_vulnerabilities']:
            summary['overall_status'] = 'fail'
            summary['recommendations'].append(f"Fix {summary['total_vulnerabilities']} dependency vulnerabilities")
        
        if summary['total_secrets'] > self.config['thresholds']['secrets_max_findings']:
            summary['overall_status'] = 'fail'
            summary['recommendations'].append(f"Remove {summary['total_secrets']} exposed secrets")
        
        # Count high severity SAST issues for Bandit
        high_severity_count = 0
        for issue in self.results['sast'].get('issues', []):
            if issue.get('issue_severity') == 'HIGH':
                high_severity_count += 1
        
        if high_severity_count > self.config['thresholds']['sast_max_high_severity']:
            summary['overall_status'] = 'fail'
            summary['recommendations'].append(f"Fix {high_severity_count} high severity code issues")
        
        return summary

    def save_report(self, output_file: str = None):
        """Save security scan report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"security_report_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Security report saved to: {output_file}")

# Integration function for existing webhook handler
async def trigger_security_scan(repo_name: str, branch: str, commit_id: str, clone_url: str = None) -> Dict[str, Any]:
    """
    Trigger security scan for GitHub webhook events
    Integrates with existing FastAPI webhook handler
    """
    print(f"[+] Starting security scan for {repo_name}:{branch} @ {commit_id}")
    
    # Construct clone URL if not provided
    if not clone_url:
        clone_url = f"https://github.com/{repo_name}.git"
    
    # Initialize scanner
    scanner = SecurityScanner()
    
    try:
        # Run security checks
        results = await scanner.run_security_checks(clone_url, branch)
        
        # Add metadata
        results['metadata'] = {
            'repository': repo_name,
            'branch': branch,
            'commit_id': commit_id,
            'scan_trigger': 'webhook_push'
        }
        
        # Save report with repository-specific naming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        repo_safe_name = repo_name.replace('/', '_')
        report_filename = f"security_report_{repo_safe_name}_{branch}_{timestamp}.json"
        scanner.save_report(report_filename)
        
        # Log summary
        summary = results['summary']
        print(f"[+] Security scan completed for {repo_name}")
        print(f"    Status: {summary['overall_status'].upper()}")
        print(f"    Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"    Secrets: {summary['total_secrets']}")
        print(f"    SAST Issues: {summary['total_sast_issues']}")
        
        if summary['overall_status'] == 'fail':
            print(f"[!] Security scan FAILED for {repo_name}")
            for rec in summary.get('recommendations', []):
                print(f"    - {rec}")
        
        return results
        
    except Exception as e:
        error_msg = f"Security scan failed for {repo_name}: {str(e)}"
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

# Example usage for webhook integration
def handle_webhook_event(webhook_data: Dict[str, Any]) -> Dict[str, Any]:
    """Handle incoming webhook event - DEPRECATED: Use trigger_security_scan instead"""
    
    # Extract repository information from webhook
    repo_url = webhook_data.get('repository', {}).get('clone_url')
    branch = webhook_data.get('ref', 'refs/heads/main').split('/')[-1]
    
    if not repo_url:
        return {'error': 'No repository URL found in webhook data'}
    
    # Initialize scanner
    scanner = SecurityScanner()
    
    # Run security checks
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(scanner.run_security_checks(repo_url, branch))
        scanner.save_report()
        return results
    finally:
        loop.close()

if __name__ == "__main__":
    # Example usage
    scanner = SecurityScanner()
    
    # For testing with a public repository
    repo_url = "https://github.com/your-username/your-repo.git"
    
    # Run async security checks
    async def main():
        results = await scanner.run_security_checks(repo_url)
        scanner.save_report()
        
        # Print summary
        print("\n=== Security Scan Summary ===")
        print(f"Overall Status: {results['summary']['overall_status']}")
        print(f"Vulnerabilities: {results['summary']['total_vulnerabilities']}")
        print(f"Secrets Found: {results['summary']['total_secrets']}")
        print(f"SAST Issues: {results['summary']['total_sast_issues']}")
        
        if results['summary']['recommendations']:
            print("\nRecommendations:")
            for rec in results['summary']['recommendations']:
                print(f"- {rec}")
    
    # Uncomment to test
    # asyncio.run(main())