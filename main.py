from flask import Flask, request, render_template_string, send_file
import concurrent.futures
import socket
import ssl
import hashlib
import requests
import io
import re
from urllib.parse import urlparse
import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

app = Flask(__name__)

HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Analiza domen</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; }
    table { border-collapse: collapse; margin-bottom: 30px; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 10px; text-align: left; vertical-align: top; }
    th { background-color: #f2f2f2; }
    textarea { width: 100%; max-width: 700px; }
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
    <h3>Domena → IP → Geolokalizacja</h3>
    <button class="copy-button" onclick="copyToClipboard('geo-output')">📋 Kopiuj Tabela IP</button>
    <div id="geo-output">{{ geo | safe }}</div>
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
    <form action="/zapisz_html" method="post" target="_blank">
      <textarea name="html" style="display:none;">{{ full_html | safe }}</textarea>
      <button class="download-button" type="submit">💾 Zapisz jako HTML</button>
    </form>
  {% endif %}
</body>
</html>
"""

# ==========================================
# FUNKCJE ZBIERAJĄCE DANE (ZAMIAST BASH)
# ==========================================

def get_ip_and_geo(domain):
    """Pobiera IP oraz Geolokalizację"""
    try:
        # Rozwiązywanie DNS w Pythonie
        ips = list(set([data[4][0] for data in socket.getaddrinfo(domain, 80)]))
        ips = [ip for ip in ips if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip)] # Tylko IPv4 dla zgodności z geo API
        
        country_code = "-"
        if ips:
            try:
                geo_response = requests.get(f"https://ipwhois.app/json/{ips[0]}", timeout=5).json()
                country_code = geo_response.get("country_code", "-")
            except:
                country_code = "?"
        
        return ", ".join(ips) if ips else "-", country_code
    except Exception:
        return "-", "-"

def get_rdap_whois(domain):
    """Pobiera i formatuje dane WHOIS używając rdap.org"""
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if resp.status_code != 200:
            return "Błąd: brak danych WHOIS"
        
        data = resp.json()
        lines = []
        
        # Ekstrakcja podstawowych pól (zabezpieczona przed brakiem kluczy)
        lines.append(f"Domain Name: {data.get('ldhName', domain).upper()}")
        lines.append(f"Registry Domain ID: {data.get('handle', '')}")
        
        # Ekstrakcja dat z 'events'
        events = data.get('events', [])
        for event in events:
            action = event.get('eventAction', '')
            date = event.get('eventDate', '')
            if action == 'registration': lines.append(f"Creation Date: {date}")
            elif action == 'expiration': lines.append(f"Registry Expiry Date: {date}")
            elif action == 'last changed': lines.append(f"Updated Date: {date}")

        # Ekstrakcja rejestratora z 'entities'
        entities = data.get('entities', [])
        registrar_name = ""
        for ent in entities:
            if 'registrar' in ent.get('roles', []):
                try:
                    # Parsowanie vCard
                    vcard = ent.get('vcardArray', [])[1]
                    for item in vcard:
                        if item[0] == 'fn':
                            registrar_name = item[3]
                            break
                except: pass
                lines.append(f"Registrar: {registrar_name}")
                lines.append(f"Registrar IANA ID: {ent.get('publicIds', [{}])[0].get('identifier', '')}")
        
        # Statusy
        for status in data.get('status', []):
            lines.append(f"Domain Status: {status}")
            
        # Nameservery
        for ns in data.get('nameservers', []):
            lines.append(f"Name Server: {ns.get('ldhName', '').upper()}")

        # Jeśli z jakiegoś powodu obiekt jest pusty
        if len(lines) <= 2:
            return "Błąd: brak szczegółowych danych w RDAP"

        return "<br>".join(lines)
    except Exception as e:
        return "Błąd: brak danych WHOIS"

def get_ssl_cert(domain):
    """Pobiera i formatuje dane Certyfikatu SSL dokładnie pod wskazany szablon"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                
        # Parsowanie binarnych danych certyfikatu przy użyciu cryptography
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Wyciąganie pól
        serial = format(cert.serial_number, 'X')
        
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            cn = "-"
            
        try:
            org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        except IndexError:
            org = "-"

        not_before = cert.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT")
        not_after = cert.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT")
        
        # Obliczanie odcisków palca (odstępy z dwukropkami jak w openssl)
        sha256_hash = hashlib.sha256(cert_der).hexdigest().upper()
        sha256 = ':'.join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))
        
        sha1_hash = hashlib.sha1(cert_der).hexdigest().upper()
        sha1 = ':'.join(sha1_hash[i:i+2] for i in range(0, len(sha1_hash), 2))
        
        lines = [
            f"Numer seryjny: {serial}",
            "Wystawiony przez:",
            f"Nazwa pospolita (CN): {cn}",
            f"Organizacja (O): {org}",
            "Okres ważności:",
            f"Ważny od dnia: {not_before}",
            f"Wygasa dnia: {not_after}",
            "Odciski:",
            f"Odcisk SHA-256: {sha256}",
            f"Odcisk SHA1: {sha1}"
        ]
        return "<br>".join(lines)
    except Exception as e:
        return "Błąd: brak certyfikatu lub połączenia"

def process_domain(domain):
    """Główny worker dla pojedynczej domeny"""
    ips, geo = get_ip_and_geo(domain)
    whois_html = get_rdap_whois(domain)
    ssl_html = get_ssl_cert(domain)
    return {
        "domain": domain,
        "ips": ips,
        "geo": geo,
        "whois": whois_html,
        "ssl": ssl_html
    }

# ==========================================
# ŚCIEŻKI FLASK
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domains_input = request.form.get("domains", "")
        raw_domains = []
        
        # Czyszczenie wejścia (wyciąganie samych nazw domen)
        for line in domains_input.splitlines():
            line = line.strip()
            if not line: continue
            
            # Odrzuć surowe IP z wprowadzania (bo pytamy o domeny)
            try:
                ipaddress.ip_address(line)
                continue
            except ValueError:
                pass
                
            if not re.match(r"^\w+://", line):
                line = "http://" + line
            try:
                host = urlparse(line).hostname or ""
            except: continue
            
            host = host.lower()
            if host.startswith("www."):
                host = host[4:]
            if host:
                raw_domains.append(host)
                
        # Unikalne, posortowane domeny
        domains = sorted(set(raw_domains))
        
        if not domains:
            return render_template_string(HTML_FORM, error="<p class='error'>Brak poprawnych domen do analizy.</p>")

        # WSPÓŁBIEŻNE WYKONYWANIE ZADAŃ (Prędkość Render.com zależy od tego!)
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {executor.submit(process_domain, dom): dom for dom in domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                results.append(future.result())

        # Sortowanie wyników po domenie dla porządku
        results = sorted(results, key=lambda x: x["domain"])

        # Generowanie HTML na podstawie zebranych słowników
        geo_table_html = """<table>
          <tr><th style="text-align: center;"><strong>Domena/Subdomena</strong></th><th style="text-align: center;"><strong>Adres IP</strong></th><th style="text-align: center;"><strong>Geo</strong></th></tr>
        """
        whois_html = ""
        cert_html = ""

        for res in results:
            dom = res["domain"]
            geo_table_html += f"<tr><td>{dom}</td><td>{res['ips']}</td><td>{res['geo']}</td></tr>"
            
            whois_html += f"<table><tr><th><strong>WHOIS – {dom}</strong></th></tr><tr><td>{res['whois']}</td></tr></table><br><br>\n"
            cert_html += f"<table><tr><th><strong>Certyfikat SSL – {dom}</strong></th></tr><tr><td>{res['ssl']}</td></tr></table><br><br>\n"
        
        geo_table_html += "</table>"
        
        # Ten wiersz zapewnia, że eksportowany plik będzie miał to samo
        full_html = f"<h3>Domena → IP → Geolokalizacja</h3>\n{geo_table_html}\n{whois_html}\n{cert_html}"

        return render_template_string(HTML_FORM,
                                      geo=geo_table_html,
                                      whois=whois_html,
                                      cert=cert_html,
                                      full_html=full_html)

    return render_template_string(HTML_FORM)

@app.route("/zapisz_html", methods=["POST"])
def zapisz_html():
    html_content = request.form.get("html", "")
    if not html_content.strip():
        return "Brak danych do zapisania", 400

    # Zapis w pamięci operacyjnej zamiast na dysku - brak kolizji między użytkownikami!
    mem_file = io.BytesIO()
    
    full_document = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Raport WHOIS i SSL</title>
  <style>
    body {{ font-family: Arial, sans-serif; padding: 20px; }}
    table {{ border-collapse: collapse; margin-bottom: 30px; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background-color: #f2f2f2; }}
  </style>
</head>
<body>
  <h2>Raport WHOIS i certyfikatów SSL</h2>
  {html_content}
</body>
</html>"""

    mem_file.write(full_document.encode('utf-8'))
    mem_file.seek(0)
    
    return send_file(mem_file, as_attachment=True, download_name="raport.html", mimetype='text/html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
