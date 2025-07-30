#!/usr/bin/env python3
"""
Flask Webhook Server for DevSecOps Security Scanner
Integrates with ngrok to receive Git webhook events
"""

from flask import Flask, request, jsonify
import json
import threading
from security_scanner import handle_webhook_event

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle incoming webhook from Git repository"""
    
    try:
        # Get webhook payload
        payload = request.get_json()
        
        if not payload:
            return jsonify({'error': 'No JSON payload received'}), 400
        
        # Log the webhook event
        print(f"Received webhook event: {payload.get('ref', 'unknown ref')}")
        print(f"Repository: {payload.get('repository', {}).get('full_name', 'unknown')}")
        
        # Run security checks in background thread to avoid timeout
        def run_security_scan():
            try:
                results = handle_webhook_event(payload)
                print("Security scan completed successfully")
                print(f"Overall status: {results.get('summary', {}).get('overall_status', 'unknown')}")
            except Exception as e:
                print(f"Security scan failed: {e}")
        
        # Start security scan in background
        thread = threading.Thread(target=run_security_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'status': 'success',
            'message': 'Security scan initiated'
        }), 200
        
    except Exception as e:
        print(f"Webhook handling error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'DevSecOps Security Scanner'
    }), 200

@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'service': 'DevSecOps Security Scanner',
        'endpoints': {
            'webhook': '/webhook (POST)',
            'health': '/health (GET)'
        }
    }), 200

if __name__ == '__main__':
    print("Starting DevSecOps Security Scanner Webhook Server...")
    print("Webhook endpoint: http://localhost:5000/webhook")
    print("Health check: http://localhost:5000/health")
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )