from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# List of test URLs to check for SSRF vulnerabilities
TEST_URLS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS Metadata service
    "http://169.254.169.253/",  # Alternate AWS metadata service
    "http://localhost/",  # Localhost test
    "http://127.0.0.1/",  # Loopback address
    "http://192.168.1.1/",  # Common internal router IP
    "http://10.0.0.1/",  # Internal network IP
    "http://[::1]/",  # IPv6 loopback
]

# Function to get baseline response

def get_baseline_response(target_url, headers):
    try:
        response = requests.get(target_url, headers=headers, timeout=5, allow_redirects=False)
        return response.text if response.status_code == 200 else None
    except requests.exceptions.RequestException:
        return None

# Function to test for SSRF

def test_ssrf(target_url):
    socketio.emit("update", {"message": f"Testing SSRF on: {target_url}"})
    results = {}

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    baseline_response = get_baseline_response(target_url, headers)

    for test_url in TEST_URLS:
        try:
            full_test_url = f"{target_url}?url={test_url}"
            response = requests.get(full_test_url, headers=headers, timeout=5, allow_redirects=False)

            if response.status_code == 200 and response.text and response.text != baseline_response:
                if any(keyword in response.text.lower() for keyword in ["metadata", "instance", "root", "password", "admin"]):
                    results[test_url] = "Potential SSRF vulnerability detected! Sensitive data exposed."
                    socketio.emit("update", {"message": f"SSRF detected: {test_url} exposed sensitive data."})
                else:
                    results[test_url] = "Response received but no sensitive data detected. Possible false positive."
            elif response.status_code in [301, 302]:
                results[test_url] = "Potential SSRF detected with redirection!"
                socketio.emit("update", {"message": f"SSRF detected: {test_url} redirected."})
            else:
                results[test_url] = f"Blocked with status code {response.status_code}"
        except requests.exceptions.Timeout:
            results[test_url] = "Timeout error - Possible firewall protection."
            socketio.emit("update", {"message": f"Timeout testing {test_url}. Possible protection in place."})
        except requests.exceptions.RequestException as e:
            results[test_url] = f"Error: {str(e)}"
            socketio.emit("update", {"message": f"Error testing {test_url}: {str(e)}"})

    return {"success": True, "message": "SSRF testing completed.", "results": results}

# Flask API Endpoint
@app.route("/api/test-ssrf", methods=["POST"])
def test_ssrf_endpoint():
    try:
        data = request.json
        target_url = data.get("url")
        
        if not target_url:
            return jsonify({"success": False, "message": "Target URL is required."}), 400
        
        result = test_ssrf(target_url)
        return jsonify(result)
    except Exception as e:
        error_message = str(e)
        return jsonify({"success": False, "message": error_message}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5007)
