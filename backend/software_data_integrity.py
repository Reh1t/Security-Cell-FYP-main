     # software_data_integrity.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

def check_software_data_integrity(url):
    socketio.emit("update", {"message": f"Checking software and data integrity on: {url}"})
    results = {
        "missing_integrity": [],
        "weak_integrity": [],
        "resources_checked": 0,
    }
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {"success": False, "message": "Failed to fetch website content."}
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Extract <script> tags with src and <link> tags for stylesheets.
        script_tags = soup.find_all("script", src=True)
        link_tags = soup.find_all("link", rel=lambda x: x and "stylesheet" in x)
        
        resources = []
        for tag in script_tags:
            src = tag.get("src")
            if src:
                resources.append({"type": "script", "url": src, "integrity": tag.get("integrity")})
        for tag in link_tags:
            href = tag.get("href")
            if href:
                resources.append({"type": "stylesheet", "url": href, "integrity": tag.get("integrity")})
                
        results["resources_checked"] = len(resources)
        
        for res in resources:
            resource_url = res["url"]
            integrity = res["integrity"]
            
            # We check both relative and absolute URLs.
            # (In production you might want to treat external resources differently.)
            if not integrity:
                results["missing_integrity"].append(resource_url)
                socketio.emit("update", {"message": f"Missing integrity attribute: {resource_url}"})
            else:
                # Check if the integrity attribute uses a strong algorithm.
                # We consider sha256, sha384, and sha512 as strong.
                if not any(algo in integrity.lower() for algo in ["sha256", "sha384", "sha512"]):
                    results["weak_integrity"].append(resource_url)
                    socketio.emit("update", {"message": f"Weak integrity algorithm used: {resource_url}"})
                    
        return {"success": True, "message": "Software and Data Integrity check completed.", "results": results}
    except Exception as e:
        error_message = f"Error checking software/data integrity on {url}: {str(e)}"
        socketio.emit("update", {"message": error_message})
        return {"success": False, "message": error_message}

@app.route("/api/test-software-data-integrity", methods=["POST", "OPTIONS"])
def test_software_data_integrity_endpoint():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "Preflight check success"}), 200
    try:
        data = request.json
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = check_software_data_integrity(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5012)
