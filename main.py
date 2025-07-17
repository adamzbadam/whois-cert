from flask import Flask, request, render_template_string
import subprocess
import os

app = Flask(__name__)

HTML_FORM = """
<!DOCTYPE html>
<html>
<head><title>Analiza domen</title></head>
<body>
  <h2>Wprowadź listę domen (jedna domena na linię):</h2>
  <form method="POST">
    <textarea name="domains" rows="10" cols="50"></textarea><br><br>
    <button type="submit">Analizuj</button>
  </form>

  {% if whois or cert %}
  <h3>📄 WHOIS</h3>
  <pre>{{ whois }}</pre>

  <h3>🔐 Certyfikaty</h3>
  <pre>{{ cert }}</pre>
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    whois_data = ""
    cert_data = ""

    if request.method == "POST":
        domains = request.form["domains"]

        # Zapisz do pliku domeny.txt
        with open("whois_cert/domeny.txt", "w") as f:
            f.write(domains.replace('\r', ''))

        # Uruchom skrypt bashowy
        subprocess.run(["bash", "whois_cert/whois_cert.sh"], check=True)

        # Wczytaj wyniki
        with open("whois_cert/whois.txt", "r") as f:
            whois_data = f.read()
        with open("whois_cert/certyfikaty.txt", "r") as f:
            cert_data = f.read()

    return render_template_string(HTML_FORM, whois=whois_data, cert=cert_data)


app.run(host="0.0.0.0", port=3000)
