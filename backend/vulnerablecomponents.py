# vulnerablecomponents.py (Final Working Version)
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
import json
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_FILE = "vulnerable_components_results.json"
VULNERABILITY_DB = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"

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

def extract_library_versions(html_content):
    libraries = {}
    matches = re.findall(r'<script[^>]+src=[\'"](.*?\.js)[\'"]', html_content, re.IGNORECASE)
    for match in matches:
        lib_name = match.split("/")[-1]
        lib_name = lib_name.replace(".min", "")
        if "-" in lib_name:
            parts = lib_name.split("-")
            name = parts[0].lower()
            version_part = parts[1]
            version = version_part.split(".js")[0]
            libraries[name] = version
    return libraries

def match_with_vulnerability_db(lib_versions):
    try:
        db_response = requests.get(VULNERABILITY_DB, timeout=10)
        db_data = db_response.json()
        vulnerable_libs = []
        for lib, version in lib_versions.items():
            if lib in db_data:
                vulnerable_versions = db_data[lib].get("vulnerable", [])
                if version in vulnerable_versions:
                    vulnerable_libs.append({
                        "library": lib,
                        "version": version,
                        "issues": db_data[lib].get("info", "No additional info")
                    })
        return vulnerable_libs
    except Exception as e:
        return [{"error": f"Failed to fetch vulnerability database: {str(e)}"}]

def check_vulnerable_components(url):
    socketio.emit("update", {"message": f"Checking vulnerable components on: {url}"})
    results = {"vulnerable_libraries": []}
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {"success": False, "message": "Failed to fetch website content."}
        content = response.text
        lib_versions = extract_library_versions(content)
        vulnerable_libs = match_with_vulnerability_db(lib_versions)
        results["vulnerable_libraries"].extend(vulnerable_libs)
        log_results(url, results)
        return {"success": True, "message": "Vulnerable component check completed.", "results": results}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.route("/api/test-vulnerable-components", methods=["POST", "OPTIONS"])
def test_vulnerable_components_endpoint():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "Preflight check success"}), 200
    try:
        data = request.json
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = check_vulnerable_components(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5009)
