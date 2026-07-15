from flask import Flask, request, abort, make_response
import requests
import re
import csv
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading

app = Flask(__name__)
ML_SERVICE_URL = "http://localhost:5001/predict"
LOG_FILE = "waf_logs.csv"

# UBA Settings
MAX_REQUESTS = 20           # Max requests allowed per window
WINDOW_SECONDS = 10         # Time window in seconds
ip_request_times = defaultdict(deque)
lock = threading.Lock()

# Initialize log file
if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip", "url", "action", "reason"])

def log_request(action, reason=""):
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            request.remote_addr,
            request.url,
            action,
            reason
        ])

def rule_based_check(input_str):
    SQLI_PATTERNS = [
        r"'.*--", r"1\s*=\s*1", r"union\s+select",
        r"exec\s*\(", r"waitfor\s+delay"
    ]
    
    XSS_PATTERNS = [
        r"<script.*?>", r"onerror\s*=", r"javascript:", 
        r"eval\s*\(", r"alert\s*\(", r"<img.*?onerror"
    ]
    
    for pattern in SQLI_PATTERNS + XSS_PATTERNS:
        if re.search(pattern, input_str, re.IGNORECASE):
            print(f"[RULE] BLOCKED: {pattern} in '{input_str[:30]}...'")
            return True
    return False

def ml_check(input_str):
    try:
        response = requests.get(f"{ML_SERVICE_URL}?q={input_str}", timeout=2)
        result = response.json()
        return result["is_malicious"]
    except Exception as e:
        print(f"[ML] Error: {e} - using rules only")
        return False

def is_anomalous_ip(ip):
    now = datetime.now()

    with lock:
        timestamps = ip_request_times[ip]
        
        # Remove old timestamps outside the sliding window
        while timestamps and timestamps[0] < now - timedelta(seconds=WINDOW_SECONDS):
            timestamps.popleft()
        
        timestamps.append(now)

        if len(timestamps) > MAX_REQUESTS:
            print(f"[UBA] BLOCKED: {ip} made {len(timestamps)} requests in {WINDOW_SECONDS}s")
            return True
    return False

@app.before_request
def waf_middleware():
    ip = request.remote_addr
    print(f"\n[WAF] {request.method} {request.url} from {ip}")

    # UBA: Block IPs that exceed request frequency
    if is_anomalous_ip(ip):
        log_request("BLOCKED", "UBA anomaly detection")
        abort(429, description="Too many requests - potential attack detected")

    # Combine GET and POST inputs
    inputs = list(request.args.values())
    if request.method == "POST":
        if request.is_json:
            inputs += list(request.get_json().values())
        else:
            inputs += list(request.form.values())
    
    for value in inputs:
        if rule_based_check(str(value)):
            log_request("BLOCKED", "Rule-based detection")
            abort(403, description="Blocked by WAF (rule-based)")
        if ml_check(str(value)):
            log_request("BLOCKED", "ML detection")
            abort(403, description="Blocked by WAF (ML)")

    log_request("ALLOWED")

@app.after_request
def add_security_headers(response):
    # Content Security Policy (CSP)
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'")

    # Anti-Clickjacking
    response.headers.setdefault("X-Frame-Options", "DENY")

    # MIME Sniffing Protection
    response.headers.setdefault("X-Content-Type-Options", "nosniff")

    # HSTS - only add for HTTPS requests
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

    # Referrer Policy
    response.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")

    return response

def hide_server_info(response):
    response.headers['Server'] = 'SecureWAF'
    response.headers.pop('X-Powered-By', None)
    return response
def secure_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; object-src 'none';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Server'] = ''
    return response

@app.route("/search")
def search():
    q = request.args.get('q', '')
    response = make_response(f"You searched for: {q}")
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; object-src 'none';"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
