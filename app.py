import os
import hashlib
import math
import re
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Demo known malware hashes (MD5)
KNOWN_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",   # empty file (demo)
}

SUSPICIOUS_PATTERNS = [
    r'eval\(.*base64_decode',
    r'exec\(',
    r'powershell -enc',
    r'<script>.*document.write\(',
    r'rm -rf',
]

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    length = len(data)
    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def scan_content(content, filename):
    md5 = hashlib.md5(content).hexdigest()
    if md5 in KNOWN_HASHES:
        return "MALICIOUS", f"Known malware signature (MD5: {md5})"

    entropy = calculate_entropy(content)
    high_entropy = entropy > 7.5

    text = ""
    try:
        text = content.decode('utf-8', errors='ignore')
    except:
        pass

    matched = []
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            matched.append(pat)

    reasons = []
    verdict = "CLEAN"
    if matched:
        verdict = "SUSPICIOUS"
        reasons.append(f"suspicious patterns: {matched}")
    if high_entropy:
        if verdict == "CLEAN":
            verdict = "SUSPICIOUS"
        reasons.append(f"high entropy ({entropy:.2f})")
    if not reasons:
        reasons.append("no threats detected")
    return verdict, "; ".join(reasons)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Aegis Sentinel – Online Scanner</title>
<style>
  body { font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px; }
  .result { padding: 15px; border-radius: 5px; margin-top: 20px; }
  .clean { background: #d4edda; color: #155724; }
  .suspicious { background: #fff3cd; color: #856404; }
  .malicious { background: #f8d7da; color: #721c24; }
</style>
</head>
<body>
  <h1>🛡️ Aegis Sentinel</h1>
  <p>Upload a file to scan for malware, viruses, and suspicious patterns.</p>
  <form method="POST" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Scan File</button>
  </form>
  {% if verdict %}
    <div class="result {{ verdict.lower() }}">
      <strong>Verdict: {{ verdict }}</strong><br>
      <small>{{ details }}</small><br>
      <small>File: {{ filename }} ({{ size }} bytes)</small>
    </div>
  {% endif %}
  <hr>
  <small>Powered by Aegis Sentinel AI – <a href="https://github.com/veldrix9-oss/Aegis-Sentinel">GitHub</a></small>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def upload():
    verdict = details = filename = size = None
    if request.method == 'POST':
        file = request.files['file']
        if file:
            content = file.read()
            filename = file.filename
            size = len(content)
            verdict, details = scan_content(content, filename)
    return render_template_string(HTML_TEMPLATE,
                                  verdict=verdict, details=details,
                                  filename=filename, size=size)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
