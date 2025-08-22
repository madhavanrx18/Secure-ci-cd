from typing import Dict, Any
from datetime import datetime

"""Thin wrapper to trigger enhanced scans.
We prefer the implementation in `newwithidor` (includes IDOR),
falling back to `security_scanner` for backward compatibility.
"""

# Resolve preferred enhanced module
_enhanced = None  # type: ignore
try:  # Prefer newwithidor where available
    import newwithidor as _enhanced  # type: ignore
except Exception:
    pass

if _enhanced is None:
    try:
        # When used as part of a package
        from . import security_scanner as _enhanced  # type: ignore
    except Exception:
        # When imported as a top-level module
        import security_scanner as _enhanced  # type: ignore


async def trigger_security_scan(repo_name: str, branch: str, commit_id: str,
                                clone_url: str = None, context: Dict = None) -> Dict[str, Any]:
    """
    Public entrypoint used by webhook handler. Delegates to the enhanced scanner.
    Kept as a thin wrapper for backward compatibility and clearer ownership.
    """
    # Prefer the enhanced implementation if present
    if hasattr(_enhanced, "trigger_enhanced_security_scan"):
        return await _enhanced.trigger_enhanced_security_scan(
            repo_name=repo_name,
            branch=branch,
            commit_id=commit_id,
            clone_url=clone_url,
            context=context,
        )

    # Fallback: construct and run directly if enhanced entry is absent
    scanner = _enhanced.EnhancedSecurityScanner()
    results = await scanner.run_security_checks(clone_url or f"https://github.com/{repo_name}.git", branch)

    # Add metadata and persist report similar to enhanced flow
    results['metadata'] = {
        'repository': repo_name,
        'branch': branch,
        'commit_id': commit_id,
        'scan_trigger': 'webhook_push',
        'context': context or {}
    }
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    repo_safe_name = repo_name.replace('/', '_')
    report_filename = f"enhanced_security_report_{repo_safe_name}_{branch}_{timestamp}.json"
    scanner.save_enhanced_report(report_filename)
    return results
