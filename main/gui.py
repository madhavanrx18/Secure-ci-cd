import sys
import os
import asyncio
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, QLineEdit
)
# Robust import: prefer newwithidor (in parent dir), fallback to security_scanner
try:
    from newwithidor import EnhancedSecurityScanner  # when run from project root
except ModuleNotFoundError:
    # Add parent directory to sys.path to locate newwithidor.py
    PARENT_DIR = os.path.dirname(os.path.dirname(__file__))
    if PARENT_DIR not in sys.path:
        sys.path.insert(0, PARENT_DIR)
    try:
        from newwithidor import EnhancedSecurityScanner
    except ModuleNotFoundError:
        # Fallback to legacy scanner
        from security_scanner import EnhancedSecurityScanner
from trigger import trigger_security_scan


class SecurityScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Scanner UI")
        self.setGeometry(300, 200, 800, 600)

        self.scanner = None
        self.last_results = None

        layout = QVBoxLayout()

        # Full scan section
        layout.addWidget(QLabel("Full Enhanced Scan (local path or repo URL):"))
        full_row = QHBoxLayout()
        self.repo_input = QLineEdit()
        self.repo_input.setPlaceholderText("/path/to/repo OR https://github.com/org/repo")
        self.branch_input = QLineEdit()
        self.branch_input.setPlaceholderText("branch (default: main)")
        full_row.addWidget(self.repo_input)
        full_row.addWidget(self.branch_input)
        layout.addLayout(full_row)

        btn_row1 = QHBoxLayout()
        self.btn_run_full = QPushButton("Run Full Enhanced Scan")
        self.btn_run_full.clicked.connect(self.run_full_scan)
        self.btn_save_report = QPushButton("Save Report")
        self.btn_save_report.clicked.connect(self.save_report)
        btn_row1.addWidget(self.btn_run_full)
        btn_row1.addWidget(self.btn_save_report)
        layout.addLayout(btn_row1)

        # Webhook-style trigger section
        layout.addWidget(QLabel("Webhook-style Scan (uses trigger_security_scan):"))
        row_repo = QHBoxLayout()
        self.repo_name_input = QLineEdit()
        self.repo_name_input.setPlaceholderText("owner/repo (e.g., madhavanrx18/Secure-ci-cd)")
        self.pr_branch_input = QLineEdit()
        self.pr_branch_input.setPlaceholderText("branch (e.g., main)")
        row_repo.addWidget(self.repo_name_input)
        row_repo.addWidget(self.pr_branch_input)
        layout.addLayout(row_repo)

        row_commit = QHBoxLayout()
        self.commit_input = QLineEdit()
        self.commit_input.setPlaceholderText("commit sha (optional)")
        self.clone_url_input = QLineEdit()
        self.clone_url_input.setPlaceholderText("clone URL (optional)")
        row_commit.addWidget(self.commit_input)
        row_commit.addWidget(self.clone_url_input)
        layout.addLayout(row_commit)

        btn_row2 = QHBoxLayout()
        self.btn_trigger = QPushButton("Trigger Webhook Scan")
        self.btn_trigger.clicked.connect(self.run_webhook_scan)
        btn_row2.addWidget(self.btn_trigger)
        layout.addLayout(btn_row2)

        # Output
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.setLayout(layout)

    def run_full_scan(self):
        self.output.clear()
        repo = self.repo_input.text().strip() or "https://github.com/madhavanrx18/Secure-ci-cd"
        branch = (self.branch_input.text().strip() or "main")
        self.output.append(f"[*] Running enhanced scan on {repo} (branch: {branch})...\n")
        try:
            self.scanner = EnhancedSecurityScanner()
            # run_security_checks is async
            results = asyncio.run(self.scanner.run_security_checks(repo, branch))
            self.last_results = results
            self._print_summary(results)
            self.output.append("\n✅ Enhanced Scan Completed!\n")
        except Exception as e:
            self.output.append(f"\n❌ Scan failed: {e}\n")

    def run_webhook_scan(self):
        self.output.append("\n[*] Triggering webhook-style enhanced scan...\n")
        repo_name = self.repo_name_input.text().strip() or "madhavanrx18/Secure-ci-cd"
        branch = self.pr_branch_input.text().strip() or "main"
        commit = self.commit_input.text().strip() or "HEAD"
        clone_url = self.clone_url_input.text().strip() or None
        try:
            results = asyncio.run(trigger_security_scan(repo_name, branch, commit, clone_url))
            self.last_results = results
            self._print_summary(results)
            self.output.append("\n✅ Webhook-style Scan Completed!\n")
        except Exception as e:
            self.output.append(f"\n❌ Trigger failed: {e}\n")

    def save_report(self):
        if not self.scanner:
            self.output.append("\n[!] No scanner instance. Run a full scan first to save a report.\n")
            return
        try:
            self.scanner.save_enhanced_report()
            self.output.append("[+] Report saved to current directory (timestamped).\n")
        except Exception as e:
            self.output.append(f"\n❌ Save report failed: {e}\n")

    def _print_summary(self, results: dict):
        summary = results.get('summary', {})
        if not summary:
            self.output.append("[!] No summary found in results.\n")
            self.output.append(str(results))
            return
        self.output.append("📊 Summary:\n")
        self.output.append(f"Overall Decision: {summary.get('overall_decision')}\n")
        self.output.append(f"Risk Score: {summary.get('risk_score')}\n")
        self.output.append(f"Deployment Recommendation: {summary.get('deployment_recommendation')}\n")
        risks = summary.get('total_risks', {})
        actions = summary.get('total_actions', {})
        self.output.append(f"Risks: {risks}\n")
        self.output.append(f"Actions: {actions}\n")
        # IDOR-specific details (if present)
        idor_specific = summary.get('idor_specific', {})
        if idor_specific:
            self.output.append("\n🔐 IDOR Summary:\n")
            self.output.append(
                f"Findings: {idor_specific.get('findings_count', 0)}, "
                f"Critical: {idor_specific.get('critical_idor', 0)}, "
                f"High: {idor_specific.get('high_idor', 0)}\n"
            )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecurityScannerGUI()
    window.show()
    sys.exit(app.exec_())
