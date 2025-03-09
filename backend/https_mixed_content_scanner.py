# https_mixed_content_scanner.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

def check_https_mixed_content(url):
    socketio.emit("update", {"message": f"Scanning {url} for HTTPS and mixed content issues..."})
    results = {
        "base_url_https": False,
        "mixed_content": [],
        "total_resources_checked": 0
    }
    
    # Check if the base URL uses HTTPS
    if url.startswith("https://"):
        results["base_url_https"] = True
    else:
        results["base_url_https"] = False
        socketio.emit("update", {"message": "Warning: Base URL is not using HTTPS!"})
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {"success": False, "message": "Failed to fetch website content."}
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Define tag-attribute pairs to check for resources
        tag_attrs = [
            ("script", "src"),
            ("link", "href"),
            ("img", "src"),
            ("iframe", "src"),
            ("video", "src"),
            ("audio", "src")
        ]
        
        mixed_resources = []
        total_resources = 0
        
        for tag, attr in tag_attrs:
            for element in soup.find_all(tag):
                resource_url = element.get(attr)
                if resource_url:
                    total_resources += 1
                    # Convert relative URL to absolute
                    absolute_url = urljoin(url, resource_url)
                    # Check if the resource URL starts with "http://"
                    if absolute_url.startswith("http://"):
                        mixed_resources.append(absolute_url)
                        socketio.emit("update", {"message": f"Insecure resource detected: {absolute_url}"})
        
        results["total_resources_checked"] = total_resources
        results["mixed_content"] = mixed_resources
        
        if mixed_resources:
            socketio.emit("update", {"message": f"Mixed content issues detected: {len(mixed_resources)} resource(s) loaded insecurely."})
        else:
            socketio.emit("update", {"message": "No mixed content issues detected."})
        
        return {"success": True, "message": "HTTPS and mixed content scan completed.", "results": results}
    
    except Exception as e:
        error_message = f"Error scanning {url} for HTTPS/mixed content: {str(e)}"
        socketio.emit("update", {"message": error_message})
        return {"success": False, "message": error_message}

@app.route("/api/test-https-mixed", methods=["POST", "OPTIONS"])
def test_https_mixed_endpoint():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "Preflight check success"}), 200
    try:
        data = request.json
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = check_https_mixed_content(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5018)
