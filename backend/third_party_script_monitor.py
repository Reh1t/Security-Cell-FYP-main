# third_party_script_monitor.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

def check_third_party_scripts(url):
    socketio.emit("update", {"message": f"Analyzing third-party scripts on: {url}"})
    results = {
        "total_scripts": 0,
        "third_party_scripts": []
    }
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {"success": False, "message": "Failed to fetch website content."}
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")
        
        script_tags = soup.find_all("script", src=True)
        results["total_scripts"] = len(script_tags)
        
        # Determine the base domain of the target URL
        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc.lower()
        
        for script in script_tags:
            src = script.get("src")
            # Normalize: if src is relative, build absolute URL using the base URL
            parsed_src = urlparse(src)
            if not parsed_src.scheme:
                # Assume relative URL
                absolute_url = requests.compat.urljoin(url, src)
                parsed_src = urlparse(absolute_url)
            else:
                absolute_url = src
            
            script_domain = parsed_src.netloc.lower()
            
            # Consider it third-party if the script's domain is different from the base domain.
            if script_domain and script_domain != base_domain:
                script_info = {
                    "url": absolute_url,
                    "domain": script_domain,
                    "uses_https": parsed_src.scheme.lower() == "https",
                    "has_integrity": bool(script.get("integrity"))
                }
                results["third_party_scripts"].append(script_info)
                socketio.emit("update", {"message": f"Third-party script detected: {absolute_url} (HTTPS: {script_info['uses_https']}, Integrity: {script_info['has_integrity']})"})
        
        socketio.emit("update", {"message": "Third-party script analysis completed."})
        return {"success": True, "message": "Third-party script check completed.", "results": results}
    except Exception as e:
        error_message = f"Error checking third-party scripts on {url}: {str(e)}"
        socketio.emit("update", {"message": error_message})
        return {"success": False, "message": error_message}

@app.route("/api/test-third-party-scripts", methods=["POST", "OPTIONS"])
def test_third_party_scripts_endpoint():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "Preflight check success"}), 200
    try:
        data = request.json
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = check_third_party_scripts(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5017)