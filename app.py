from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import time, requests, os, webbrowser, threading

# ---------------------------
# Flask App Setup
# ---------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/news")
def news():
    return render_template("news.html")

# ---------------------------
# VirusTotal API Config
# ---------------------------
# Your API key directly added here for local testing
VIRUSTOTAL_API_KEY = "46f7c10acbb9f905fcadbcf0ae19cdd3e28b7ebe2e63abca0b6ed89409e5b44e"  # safer than hardcoding

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_FILE_SCAN = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS = "https://www.virustotal.com/api/v3/analyses/"

HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else {}


# ---------------------------
# Helper Function
# ---------------------------
def compute_danger(stats: dict) -> float:
    """Calculate danger percentage based on malicious and suspicious reports."""
    if not stats:
        return 0.0
    total = sum(int(stats.get(k, 0)) for k in stats.keys())
    if total == 0:
        return 0.0

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    return round(((malicious + suspicious) / total) * 100.0, 2)

# ---------------------------
# Health Check Endpoint
# ---------------------------
@app.route("/health", methods=["GET"])
def health():
    """Simple endpoint to check API health and key configuration"""
    ok = bool(VIRUSTOTAL_API_KEY)
    return jsonify({"status": "ok" if ok else "missing_api_key"}), 200

# ---------------------------
# URL Scan Endpoint
# ---------------------------
@app.route("/scan", methods=["POST"])
def scan_url():
    """Scan a URL using the VirusTotal API."""
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "Missing VirusTotal API key"}), 500

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Step 1: Submit URL to VirusTotal
        submit = requests.post(VT_URL_SCAN, headers=HEADERS, data={"url": url}, timeout=30)
        if submit.status_code >= 400:
            return jsonify({
                "error": f"Submit failed: {submit.status_code}",
                "details": submit.text
            }), 502

        analysis_id = submit.json().get("data", {}).get("id")
        if not analysis_id:
            return jsonify({
                "error": "No analysis ID returned",
                "details": submit.text
            }), 502

        # Step 2: Poll VirusTotal for results
        deadline = time.time() + 25
        last_payload = {}
        while time.time() < deadline:
            resp = requests.get(VT_ANALYSIS + analysis_id, headers=HEADERS, timeout=30)
            if resp.status_code >= 400:
                return jsonify({
                    "error": f"Analysis fetch failed: {resp.status_code}",
                    "details": resp.text
                }), 502

            payload = resp.json()
            last_payload = payload
            status = payload.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                break
            time.sleep(1.2)

        # Step 3: Extract analysis results
        attributes = last_payload.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {}) or {}
        total = sum(int(stats.get(k, 0)) for k in stats.keys())
        danger_percentage = compute_danger(stats)

        return jsonify({
            "url": url,
            "status": attributes.get("status", "unknown"),
            "total": total,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "timeout": int(stats.get("timeout", 0)),
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "danger_percentage": danger_percentage,
            "analysis_id": analysis_id
        })

    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

# ---------------------------
# File Scan Endpoint
# ---------------------------
@app.route("/scan_file", methods=["POST"])
def scan_file():
    """Scan a file (PDF, DOCX, APK, etc.) using the VirusTotal API."""
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "Missing VirusTotal API key"}), 500

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    try:
        # Step 1: Submit file to VirusTotal
        files = {"file": (file.filename, file.stream, file.mimetype)}
        submit = requests.post(VT_FILE_SCAN, headers=HEADERS, files=files, timeout=60)
        if submit.status_code >= 400:
            return jsonify({
                "error": f"File submit failed: {submit.status_code}",
                "details": submit.text
            }), 502

        analysis_id = submit.json().get("data", {}).get("id")
        if not analysis_id:
            return jsonify({
                "error": "No analysis ID returned",
                "details": submit.text
            }), 502

        # Step 2: Poll VirusTotal for results
        deadline = time.time() + 90
        last_payload = {}
        while time.time() < deadline:
            resp = requests.get(VT_ANALYSIS + analysis_id, headers=HEADERS, timeout=30)
            if resp.status_code >= 400:
                return jsonify({
                    "error": f"Analysis fetch failed: {resp.status_code}",
                    "details": resp.text
                }), 502

            payload = resp.json()
            last_payload = payload
            status = payload.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                break
            time.sleep(2)

        # Step 3: Extract analysis results
        attributes = last_payload.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {}) or {}
        total = sum(int(stats.get(k, 0)) for k in stats.keys())
        danger_percentage = compute_danger(stats)

        return jsonify({
            "filename": file.filename,
            "status": attributes.get("status", "unknown"),
            "total": total,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "timeout": int(stats.get("timeout", 0)),
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "danger_percentage": danger_percentage,
            "analysis_id": analysis_id
        })

    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

# ---------------------------
# Run Flask App
# ---------------------------
# Open browser automatically after the server starts
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000/")
    

if __name__ == "__main__":
    print("🚀 Cyber Scanner backend running at http://127.0.0.1:5000")
    threading.Timer(1.5, open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=True)