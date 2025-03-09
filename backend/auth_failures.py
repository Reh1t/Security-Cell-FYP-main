# auth_failures.py - Detailed Test Logging Version
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# Load authentication endpoints from endpoint.txt
def load_auth_endpoints(file_path="endpoints.txt"):
    endpoints = []
    try:
        with open(file_path, "r") as f:
            endpoints = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading endpoints from {file_path}: {str(e)}")
    return endpoints

AUTH_ENDPOINTS = load_auth_endpoints()
if not AUTH_ENDPOINTS:
    # Fallback if file is missing or empty
    AUTH_ENDPOINTS = ["/login", "/admin", "/authenticate", "/user/login", "/signin",
                      "/signup", "/dashboard", "/account", "/session", "/auth"]

# Keywords to identify session cookies
SESSION_KEYWORDS = ["session", "auth", "token", "jwt"]

def check_authentication_failures(base_url):
    socketio.emit("update", {"message": f"Checking authentication weaknesses on: {base_url}"})
    detailed_tests = []  # List to record every test performed

    results = {
        "exposed_auth_endpoints": [],
        "missing_auth_headers": [],
        "weak_session_cookies": [],
        "detailed_tests": detailed_tests,
    }

    try:
        # 1. Check for exposed authentication endpoints.
        for endpoint in AUTH_ENDPOINTS:
            url = f"{base_url.rstrip('/')}{endpoint}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)  # prevent auto-redirects
                test_message = f"Tested endpoint {url}: Status Code {response.status_code}."
                if response.status_code in [200, 401, 403]:
                    content = response.text.lower()
                    if "<form" in content and 'type="password"' in content:
                        results["exposed_auth_endpoints"].append(url)
                        test_message += " Exposed authentication endpoint detected."
                        socketio.emit("update", {"message": f"Exposed authentication endpoint detected: {url}"})
                    else:
                        test_message += " No login form detected."
                else:
                    test_message += " Endpoint not accessible."
                detailed_tests.append(test_message)
            except Exception as ex:
                error_msg = f"Error testing endpoint {url}: {str(ex)}"
                detailed_tests.append(error_msg)
                socketio.emit("update", {"message": error_msg})

        # 2. Check for missing WWW-Authenticate header.
        try:
            response = requests.get(base_url, timeout=5)
            header_test = f"Base URL {base_url} returned status {response.status_code}. Headers: {dict(response.headers)}."
            if response.status_code == 401 and "WWW-Authenticate" not in response.headers:
                results["missing_auth_headers"].append("WWW-Authenticate header is missing")
                header_test += " Missing WWW-Authenticate header detected."
                socketio.emit("update", {"message": "Missing WWW-Authenticate header on base URL."})
            else:
                header_test += " WWW-Authenticate header check passed."
            detailed_tests.append(header_test)
        except Exception as ex:
            error_msg = f"Error checking headers on {base_url}: {str(ex)}"
            detailed_tests.append(error_msg)
            socketio.emit("update", {"message": error_msg})

        # 3. Check for weak session cookie attributes.
        try:
            cookies = response.cookies
            cookie_test = f"Cookies from {base_url}: {[cookie.name for cookie in cookies]}."
            for cookie in cookies:
                if any(keyword in cookie.name.lower() for keyword in SESSION_KEYWORDS):
                    if not cookie.secure or not cookie.rest.get("HttpOnly", False):
                        results["weak_session_cookies"].append(cookie.name)
                        cookie_test += f" Weak session cookie detected: {cookie.name}."
                        socketio.emit("update", {"message": f"Weak session cookie detected: {cookie.name}"})
            detailed_tests.append(cookie_test)
        except Exception as ex:
            error_msg = f"Error checking cookies on {base_url}: {str(ex)}"
            detailed_tests.append(error_msg)
            socketio.emit("update", {"message": error_msg})

        # Provide explicit messages if no issues are found.
        if not results["exposed_auth_endpoints"]:
            results["exposed_auth_endpoints"] = "No exposed authentication endpoints detected."
            detailed_tests.append("No exposed authentication endpoints detected.")
        if not results["missing_auth_headers"]:
            results["missing_auth_headers"] = "No missing authentication headers detected."
            detailed_tests.append("No missing WWW-Authenticate header detected.")
        if not results["weak_session_cookies"]:
            results["weak_session_cookies"] = "No weak session cookies detected."
            detailed_tests.append("No weak session cookies detected.")

        return {"success": True, "message": "Authentication check completed.", "results": results}

    except Exception as e:
        error_message = f"Error testing {base_url}: {str(e)}"
        socketio.emit("update", {"message": error_message})
        return {"success": False, "message": error_message}

@app.route("/api/test-auth-failures", methods=["POST", "OPTIONS"])
def test_auth_failures_endpoint():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "Preflight check success"}), 200
    try:
        data = request.json
        base_url = data.get("url")
        if not base_url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = check_authentication_failures(base_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5011)
