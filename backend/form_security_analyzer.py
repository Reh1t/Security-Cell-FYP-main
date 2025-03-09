# form_security_analyzer.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

def analyze_forms(url):
    socketio.emit("update", {"message": f"Analyzing forms on: {url}"})
    results = {"total_forms": 0, "forms": []}
    try:
        response = requests.get(url, timeout=10)
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")
        forms = soup.find_all("form")
        results["total_forms"] = len(forms)
        
        for i, form in enumerate(forms):
            form_info = {}
            form_info["index"] = i + 1
            form_info["action"] = form.get("action")
            form_info["method"] = form.get("method", "GET").upper()
            form_info["issues"] = []
            
            # 1. Check form action URL: it should be present and use HTTPS.
            action = form.get("action")
            if action:
                if not action.lower().startswith("https://"):
                    form_info["issues"].append("Form action is not secure (not HTTPS).")
            else:
                form_info["issues"].append("Form action is missing.")
            
            # 2. Check form method: ideally it should be POST for sensitive data.
            if form_info["method"] != "POST":
                form_info["issues"].append(f"Form method is {form_info['method']} (expected POST).")
            
            # 3. Check for CAPTCHA presence.
            captcha_found = False
            # Look for elements with class or id containing "captcha"
            if form.find(attrs={"class": re.compile("captcha", re.I)}) or form.find(attrs={"id": re.compile("captcha", re.I)}):
                captcha_found = True
            # Look for common CAPTCHA widget indicators
            if "g-recaptcha" in str(form).lower() or "hcaptcha" in str(form).lower():
                captcha_found = True
            if not captcha_found:
                form_info["issues"].append("No CAPTCHA detected in the form.")
            
            # 4. Check for CSRF token in hidden inputs (looking for "csrf" in the name).
            csrf_found = False
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            for input_elem in hidden_inputs:
                if "csrf" in input_elem.get("name", "").lower():
                    csrf_found = True
                    break
            if not csrf_found:
                form_info["issues"].append("No CSRF token detected in the form.")
            
            # 5. Check for an onsubmit attribute (could be used for form jacking).
            onsubmit = form.get("onsubmit")
            if onsubmit:
                form_info["issues"].append("Form has an onsubmit attribute which may be exploited.")
            
            results["forms"].append(form_info)
            socketio.emit("update", {"message": f"Form {i+1} analysis: {form_info}"})
        
        return {"success": True, "message": "Form security analysis completed.", "results": results}
    except Exception as e:
        error_message = f"Error analyzing forms on {url}: {str(e)}"
        socketio.emit("update", {"message": error_message})
        return {"success": False, "message": error_message}

@app.route("/api/test-form-security", methods=["POST", "OPTIONS"])
def test_form_security_endpoint():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "Preflight check success"}), 200
    try:
        data = request.json
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "message": "URL is required."}), 400
        result = analyze_forms(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5016)