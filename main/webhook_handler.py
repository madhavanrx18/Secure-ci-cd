import json
import hmac
import hashlib
import os
import asyncio
from security_scanner import trigger_security_scan

# TODO: Use environment variable or config file
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "7780ccfb32a33df7f884e85353033070bf7e4a724e39dc0760bb2fb66849100e")

async def handle_github_event(payload_bytes: bytes, headers: dict):
    # Verify signature
    signature = headers.get("X-Hub-Signature-256")
    if not verify_signature(payload_bytes, signature):
        raise ValueError("Invalid signature")

    payload = json.loads(payload_bytes)
    event = headers.get("X-GitHub-Event", "unknown")

    if event == "push":
        repo_name = payload['repository']['full_name']
        branch = payload['ref'].split('/')[-1]
        commit_id = payload['after']
        clone_url = payload['repository']['clone_url']
        
        print(f"[+] Push event received for {repo_name} on branch {branch}, commit {commit_id}")
        
        # Skip if it's a deletion (commit_id would be all zeros)
        if commit_id == "0000000000000000000000000000000000000000":
            print(f"[!] Skipping security scan - branch deletion detected")
            return
        
        # Trigger security scanner asynchronously
        try:
            # Run security scan in background to avoid blocking webhook response
            asyncio.create_task(
                run_security_scan_background(repo_name, branch, commit_id, clone_url)
            )
            print(f"[+] Security scan initiated for {repo_name}")
        except Exception as e:
            print(f"[-] Failed to initiate security scan: {str(e)}")
            
    elif event == "pull_request":
        action = payload['action']
        print(f"[+] Pull request event: {action}")
        
        # Handle PR events (optional)
        if action in ['opened', 'synchronize', 'reopened']:
            repo_name = payload['repository']['full_name']
            branch = payload['pull_request']['head']['ref']
            commit_id = payload['pull_request']['head']['sha']
            clone_url = payload['repository']['clone_url']
            pr_number = payload['pull_request']['number']
            
            print(f"[+] PR #{pr_number} security scan for {repo_name}:{branch}")
            
            # Trigger security scan for PR
            try:
                asyncio.create_task(
                    run_security_scan_background(
                        repo_name, branch, commit_id, clone_url, 
                        context=f"PR-{pr_number}"
                    )
                )
                print(f"[+] PR security scan initiated for {repo_name}")
            except Exception as e:
                print(f"[-] Failed to initiate PR security scan: {str(e)}")
    else:
        print(f"[-] Unhandled event type: {event}")

async def run_security_scan_background(repo_name: str, branch: str, commit_id: str, 
                                     clone_url: str, context: str = "push"):
    """
    Run security scan in background
    This prevents the webhook from timing out while scan is running
    """
    try:
        print(f"[+] Background security scan starting for {repo_name} ({context})")
        
        # Run the security scan
        results = await trigger_security_scan(repo_name, branch, commit_id, clone_url)
        
        # Handle results
        if 'error' in results:
            print(f"[-] Security scan error for {repo_name}: {results['error']}")
        else:
            summary = results.get('summary', {})
            status = summary.get('overall_status', 'unknown')
            print(f"[+] Security scan completed for {repo_name}: {status.upper()}")
            
            # Optional: Add notification logic here
            await handle_scan_results(repo_name, branch, commit_id, results, context)
            
    except Exception as e:
        print(f"[-] Background security scan failed for {repo_name}: {str(e)}")

async def handle_scan_results(repo_name: str, branch: str, commit_id: str, 
                            results: dict, context: str):
    """
    Handle security scan results - customize this for your needs
    """
    summary = results.get('summary', {})
    status = summary.get('overall_status', 'unknown')
    
    # Log detailed results
    print(f"[+] Scan Results for {repo_name} ({context}):")
    print(f"    Overall Status: {status.upper()}")
    print(f"    Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print(f"    Secrets Found: {summary.get('total_secrets', 0)}")
    print(f"    SAST Issues: {summary.get('total_sast_issues', 0)}")
    
    if status == 'fail':
        print(f"[!] SECURITY ISSUES DETECTED in {repo_name}!")
        recommendations = summary.get('recommendations', [])
        for i, rec in enumerate(recommendations, 1):
            print(f"    {i}. {rec}")
        
        # TODO: Add your notification logic here
        # Examples:
        # - Send Slack notification
        # - Create GitHub issue
        # - Send email alert
        # - Update external dashboard
        # - Block deployment pipeline
        
        # Example notification call (implement as needed):
        # await send_security_alert(repo_name, branch, commit_id, summary)
    
    # Optional: Store results in database
    # await store_scan_results(repo_name, branch, commit_id, results)

def verify_signature(payload: bytes, signature: str) -> bool:
    if not signature:
        return False
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return False
    mac = hmac.new(GITHUB_SECRET.encode(), msg=payload, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)

# Optional: Add these notification functions as needed

async def send_security_alert(repo_name: str, branch: str, commit_id: str, summary: dict):
    """
    Send security alert notification
    Implement based on your notification preferences
    """
    # Example Slack notification
    # slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    # if slack_webhook_url:
    #     message = {
    #         "text": f"🚨 Security Issues Detected in {repo_name}",
    #         "attachments": [{
    #             "color": "danger",
    #             "fields": [
    #                 {"title": "Repository", "value": repo_name, "short": True},
    #                 {"title": "Branch", "value": branch, "short": True},
    #                 {"title": "Vulnerabilities", "value": str(summary.get('total_vulnerabilities', 0)), "short": True},
    #                 {"title": "Secrets", "value": str(summary.get('total_secrets', 0)), "short": True},
    #                 {"title": "SAST Issues", "value": str(summary.get('total_sast_issues', 0)), "short": True}
    #             ]
    #         }]
    #     }
    #     # Send to Slack
    #     requests.post(slack_webhook_url, json=message)
    
    print(f"[!] Security alert would be sent for {repo_name} (implement notification logic)")

async def store_scan_results(repo_name: str, branch: str, commit_id: str, results: dict):
    """
    Store scan results in database
    Implement based on your database choice
    """
    # Example database storage
    # scan_record = {
    #     'repository': repo_name,
    #     'branch': branch,
    #     'commit_id': commit_id,
    #     'timestamp': datetime.now(),
    #     'results': results
    # }
    # await database.insert('security_scans', scan_record)
    
    print(f"[+] Scan results would be stored for {repo_name} (implement database logic)")