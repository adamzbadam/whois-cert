from flask import Flask, request, render_template_string, send_file
import subprocess
import os
import re
import socket
import requests
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

# Ścieżki
BASE_DIR = os.path.dirname(__file__)
PROJECT_DIR = BASE_DIR
STATIC_DIR = os.path.join(PROJECT_DIR, "static")

DOMAINS_FILE = os.path.join(PROJECT_DIR, "domeny.txt")
WHOIS_INPUT = os.path.join(PROJECT_DIR, "whois_input.txt")
WHOIS_FILE = os.path.join(PROJECT_DIR, "whois.txt")
CERT_FILE = os.path.join(PROJECT_DIR, "certyfikaty.txt")
EXPORT_FILE = os.path.join(STATIC_DIR, "raport.html")

HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Analiza domen</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; }
    table { border-collapse: collapse; margin-bottom: 30px; width: 100%%; }
    th, td { border: 1px solid #ccc; padding: 10px; text-align: left; vertical-align: top; }
    th { background-color: #f2f2f2; }
    textarea { width: 100%%; max-width: 700px; }
    .error { color: red; font-weight: bold; }
    .copy-button, .download-button {
      margin: 10px 10px 20px 0;
      padding: 6px 12px;
      font-size: 14px;
      cursor: pointer;
    }
  </style>
  <script>
    function copyToClipboard(id) {
      const el = document.getElementById(id);
      if (!el) return;

      const html = el.innerHTML;
      const temp = document.createElement("div");
      temp.innerHTML = html;
      temp.contentEditable = true;
      temp.style.position = "absolute";
      temp.style.left = "-9999px";
      document.body.appendChild(temp);

      const range = document.createRange();
      range.selectNodeContents(temp);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      document.execCommand("copy");

      document.body.removeChild(temp);
      alert("📋 Skopiowano tabelę HTML do schowka.");
    }
  </script>
</head>
<body>
  <h2>Wprowadź listę domen (jedna domena na linię):</h2>

  <form method="POST" id="domainForm">
    <textarea name="domains" rows="10"></textarea><br><br>
    <input type="submit" value="Analizuj">
  </form>

  {{ error | safe }}

  {% if geo %}
    {{ geo | safe }}
  {% endif %}

  {% if whois %}
    <h3>WHOIS</h3>
    <button class="copy-button" onclick="copyToClipboard('whois-output')">📋 Kopiuj WHOIS</button>
    <div id="whois-output">{{ whois | safe }}</div>
  {% endif %}

  {% if cert %}
    <h3>Certyfikaty SSL</h3>
    <button class="copy-button" onclick="copyToClipboard('cert-output')">📋 Kopiuj Certyfikaty</button>
    <div id="cert-output">{{ cert | safe }}</div>
  {% endif %}

  {% if whois or cert or geo %}
    <form action="/zapisz_html" method="post">
      <textarea name="html" style="display:none;">{{ full_html | safe }}</textarea>
      <button class="download-button" type="submit">💾 Zapisz jako HTML</button>
    </form>
  {% endif %}
</body>
</html>
"""


def resolve_ip_addresses(domain):
    try:
        result = subprocess.run(["dig", "+short", domain],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                timeout=5)

        lines = result.stdout.decode("utf-8", errors="ignore").splitlines()
        ips = []

        for line in lines:
            line = line.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                ips.append(line)

        return ips

    except Exception as e:
        print(f"[ERROR] resolve_ip_addresses: {e}")
        return []


def resolve_domains_with_geo(domains):
    result_rows = []
    seen = set()

    for domain in domains:
        domain = domain.strip()
        if not domain or domain in seen:
            continue
        seen.add(domain)

        ip_list = resolve_ip_addresses(domain)
        country_code = "-"

        if ip_list:
            try:
                geo_response = requests.get(
                    f"https://ipwhois.app/json/{ip_list[0]}", timeout=5)
                geo_data = geo_response.json()
                country_code = geo_data.get("country_code", "-")
            except Exception:
                country_code = "?"

        ip_str = ", ".join(ip_list) if ip_list else "-"
        result_rows.append((domain, ip_str, country_code))

    return result_rows


def whois_text_to_table(whois_data):
    blocks = whois_data.strip().split(
        '----------------------------------------')
    html = ""
    for block in blocks:
        if not block.strip():
            continue
        lines = block.strip().split('\n')
        title = ""
        content_lines = []
        for line in lines:
            if line.lower().startswith("domena:"):
                domain = line.split(":", 1)[1].strip()
                title = f"WHOIS – {domain}"
            else:
                content_lines.append(line.strip())
        content_html = "<br>".join(content_lines)
        if not title:
            title = "WHOIS – (brak domeny)"
        html += f"""
        <table>
          <tr><th><strong>{title}</strong></th></tr>
          <tr><td>{content_html}</td></tr>
        </table>
        <br><br>
        """
    return html


def cert_text_to_table(cert_data):
    blocks = cert_data.strip().split(
        '----------------------------------------')
    html = ""
    for block in blocks:
        if not block.strip():
            continue
        lines = block.strip().split('\n')
        title = ""
        content_lines = []
        for line in lines:
            if line.lower().startswith("domena:"):
                domain = line.split(":", 1)[1].strip()
                title = f"Certyfikat SSL – {domain}"
            else:
                content_lines.append(line.strip())
        content_html = "<br>".join(content_lines)
        if not title:
            title = "Certyfikat SSL – (brak domeny)"
        html += f"""
        <table>
          <tr><th><strong>{title}</strong></th></tr>
          <tr><td>{content_html}</td></tr>
        </table>
        <br><br>
        """
    return html


@app.route("/", methods=["GET", "POST"])
def index():
    whois_data = ""
    cert_data = ""
    error_html = ""
    geo_table_html = ""

    if request.method == "POST":
        domains = request.form["domains"]
        os.makedirs(PROJECT_DIR, exist_ok=True)

        raw_domains = []
        whois_domains = []

        for line in domains.splitlines():
            line = line.strip()
            if not line:
                continue
            raw_domains.append(line)

            try:
                ipaddress.ip_address(line)
                whois_domains.append(line)
                continue
            except ValueError:
                pass

            if not re.match(r"^\w+://", line):
                line = "http://" + line
            try:
                host = urlparse(line).hostname or ""
            except:
                continue

            host = host.lower()
            if host.startswith("www."):
                host = host[4:]
            parts = host.split(".")
            if len(parts) >= 2:
                whois_domains.append(".".join(parts[-2:]))
            else:
                whois_domains.append(host)

        with open(DOMAINS_FILE, "w") as f:
            f.write("\n".join(sorted(set(raw_domains))))
        with open(WHOIS_INPUT, "w") as f:
            f.write("\n".join(sorted(set(whois_domains))))

        try:
            subprocess.run([
                "bash",
                os.path.join(PROJECT_DIR, "whois_cert.sh"), DOMAINS_FILE,
                WHOIS_INPUT, WHOIS_FILE, CERT_FILE
            ],
                           check=True)

            with open(WHOIS_FILE, "r") as f:
                whois_data = f.read()
            with open(CERT_FILE, "r") as f:
                cert_data = f.read()
        except subprocess.CalledProcessError as e:
            error_html = f"<p class='error'>❌ Błąd uruchamiania skryptu: {e}</p>"
        except Exception as e:
            error_html = f"<p class='error'>❌ Inny błąd: {e}</p>"

        geo_rows = resolve_domains_with_geo(raw_domains)
        if geo_rows:
            geo_table_html = """
            <h3>Domena → IP → Geolokalizacja</h3>
            <button class="copy-button" onclick="copyToClipboard('geo-output')">📋 Kopiuj Tabela IP</button>
            <div id="geo-output">
            <table>
              <tr><th style="text-align: center;"><strong>Domena/Subdomena</strong></th><th style="text-align: center;"><strong>Adres IP</strong></th><th style="text-align: center;"><strong>Geo</strong></th></tr>
            """
            for dom, ip_addr, loc in geo_rows:
                geo_table_html += f"<tr><td>{dom}</td><td>{ip_addr}</td><td>{loc}</td></tr>"
            geo_table_html += "</table></div>"

    whois_html = whois_text_to_table(whois_data)
    cert_html = cert_text_to_table(cert_data)
    full_html = geo_table_html + whois_html + cert_html

    return render_template_string(HTML_FORM,
                                  whois=whois_html,
                                  cert=cert_html,
                                  geo=geo_table_html,
                                  error=error_html,
                                  full_html=full_html)


@app.route("/zapisz_html", methods=["POST"])
def zapisz_html():
    html_content = request.form.get("html", "")
    if not html_content.strip():
        return "Brak danych do zapisania", 400

    try:
        os.makedirs(STATIC_DIR, exist_ok=True)
        full_document = f"""<!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Raport WHOIS i SSL</title>
          <style>
            body {{
              font-family: Arial, sans-serif;
              padding: 20px;
            }}
            table {{
              border-collapse: collapse;
              margin-bottom: 30px;
              width: 100%;
            }}
            th, td {{
              border: 1px solid #ccc;
              padding: 10px;
              text-align: left;
              vertical-align: top;
            }}
            th {{
              background-color: #f2f2f2;
            }}
          </style>
        </head>
        <body>
          <h2>Raport WHOIS i certyfikatów SSL</h2>
          {html_content}
        </body>
        </html>
        """
        with open(EXPORT_FILE, "w", encoding="utf-8") as f:
            f.write(full_document)
        return send_file(EXPORT_FILE, as_attachment=True)
    except Exception as e:
        return f"Błąd zapisu: {e}", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
