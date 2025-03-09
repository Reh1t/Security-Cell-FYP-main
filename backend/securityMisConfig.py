from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
from urllib.parse import urlparse
import threading
import json
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_FILE = "security_scan_results.json"

# List of security headers to check
SECURITY_HEADERS = [
    "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers", "Expect-CT", "Cache-Control", "Pragma", "Server",
    "X-Permitted-Cross-Domain-Policies", "X-DNS-Prefetch-Control"
]

# Sensitive files to check
SENSITIVE_FILES = [
    "/.env", "/config.php", "/wp-config.php", "/wp-config-sample.php", "/.git/config", "/.gitignore", "/.htaccess",
    "/.htpasswd", "/settings.py", "/.bash_history", "/.bashrc", "/.zshrc", "/.npmrc", "/.yarnrc",
    "/backup.zip", "/database.sql", "/db.sql", "/dump.sql", "/logs/error.log", "/logs/access.log",
    "/debug.log", "/backup.tar.gz", "/.DS_Store", "/Thumbs.db",
    "/messages.php", "/message.php", "/subscribe.php", "/unsubscribe.php", "/register.php", "/login.php",
    "/admin.php", "/admin-login.php", "/admin-login.html", "/administrator.php", "/user.php", "/panel.php",
    "/dashboard.php", "/phpinfo.php", "/server-status", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/web.config"
]

ERROR_PATTERNS = ["not found", "access denied", "403 forbidden", "error id", "forbidden", "vercel"]

def log_results(url, results):
    log_data = {"url": url, "results": results}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as file:
            data = json.load(file)
    else:
        data = []
    data.append(log_data)
    with open(LOG_FILE, "w") as file:
        json.dump(data, file, indent=4)

def check_security_misconfiguration(url):
    socketio.emit("update", {"message": f"Testing security misconfiguration on: {url}"})
    results = {"missing_headers": [], "exposed_files": []}
    parsed_base_url = urlparse(url).netloc

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        homepage_content = response.text.strip().lower()
        
        for header in SECURITY_HEADERS:
            if header not in headers:
                results["missing_headers"].append(header)
                socketio.emit("update", {"message": f"Missing security header: {header}"})
        
        def test_file(file_path):
            test_url = f"{url.rstrip('/')}{file_path}"
            file_response = requests.get(test_url, timeout=5, allow_redirects=True)
            
            status_code = file_response.status_code
            final_url = file_response.url
            parsed_final_url = urlparse(final_url).netloc
            content = file_response.text.strip().lower()
            
            if "x-vercel-id" in file_response.headers or any(pattern in content for pattern in ERROR_PATTERNS):
                return
            
            if content == homepage_content:
                return
            
            if file_path == "/robots.txt" and status_code == 200:
                results["exposed_files"].append(test_url)
                socketio.emit("update", {"message": f"Exposed sensitive file detected: {test_url}"})
                return
            
            if status_code in [200, 401, 402, 403] and not any(pattern in content for pattern in ERROR_PATTERNS):
                results["exposed_files"].append(test_url)
                socketio.emit("update", {"message": f"Exposed sensitive file detected: {test_url}"})
        
        threads = []
        for file_path in SENSITIVE_FILES:
            thread = threading.Thread(target=test_file, args=(file_path,))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        log_results(url, results)
        return {"success": True, "message": "Security misconfiguration check completed.", "results": results}
    except Exception as e:
        error_message = f"Error testing {url}: {str(e)}"
        socketio.emit("update", {"message": error_message})
        return {"success": False, "message": error_message}

@app.route("/api/test-security-misconfig", methods=["POST", "OPTIONS"])
def test_security_misconfig_endpoint():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "Preflight check success"}), 200
    try:
        data = request.json
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = check_security_misconfiguration(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5008)