from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CorpNet Self-Service Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }
        .container { max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .result { background: #eee; padding: 10px; margin-top: 20px; white-space: pre-wrap; font-family: monospace; border-left: 4px solid #007bff; }
        input[type="text"] { width: 70%; padding: 10px; margin-right: 10px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CorpNet EAP/VPN Diagnostic Portal</h1>
        <p>Use this tool to test connectivity to corporate network gateways before attempting to authenticate.</p>
        <form method="POST">
            <input type="text" name="target" placeholder="Enter IP or domain (e.g. 8.8.8.8)" required>
            <button type="submit">Run Ping Test</button>
        </form>
        {% if output %}
        <div class="result">{{ output }}</div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    if request.method == "POST":
        target = request.form.get("target", "")
        # VULNERABILITY: Command Injection
        # The user input is passed directly to the shell without sanitization.
        try:
            # Execute ping command with user input
            command = f"ping -c 3 {target}"
            # Using shell=True makes this extremely vulnerable
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            output = result
        except subprocess.CalledProcessError as e:
            output = f"Command failed:\n{e.output}"
        except Exception as e:
            output = str(e)
            
    return render_template_string(HTML_TEMPLATE, output=output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
