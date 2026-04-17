#!/bin/bash

CERT_INPUT="$1"
WHOIS_INPUT="$2"
WHOIS_OUT="$3"
CERT_OUT="$4"

# Wyczyść stare pliki wynikowe
> "$WHOIS_OUT"
> "$CERT_OUT"

# ------------------------------------
# 🔍 WHOIS
# ------------------------------------
while IFS= read -r domain || [[ -n "$domain" ]]; do
    domain=$(echo "$domain" | xargs)
    if [[ -z "$domain" ]]; then continue; fi

    echo "🌐 WHOIS dla $domain"

    whois_text=""

    if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # IP – zapytaj IANA najpierw
        iana_result=$(whois -h whois.iana.org -p 43 "$domain" 2>/dev/null)
        refer_server=$(echo "$iana_result" | grep -i "^refer:" | awk '{print $2}')

        if [[ -n "$refer_server" ]]; then
            whois_text=$(whois -h "$refer_server" "$domain" 2>/dev/null)
        else
            whois_text="$iana_result"
        fi
    else
        # Domena – przez API
        response=$(curl -s --max-time 20 "https://api.whois.vu/?q=$domain")
        whois_text=$(echo "$response" | jq -r '.whois // empty' | sed 's/\\r\\n/\n/g; s/\\n/\n/g; s/\\t/\t/g; s/\\"/"/g')
    fi

    # Oczyść wynik
    whois_text=$(echo "$whois_text" | sed 's/\r//g')

    if [[ -z "$whois_text" ]]; then
        echo -e "Domena: $domain\nBłąd: brak danych WHOIS\n----------------------------------------\n" >> "$WHOIS_OUT"
    else
        {
            echo "Domena: $domain"
            echo "$whois_text" | awk '/>>>/ {exit} {print}' | sed 's/^[ \t]*//'
            echo -e "----------------------------------------\n"
        } >> "$WHOIS_OUT"
    fi
done < "$WHOIS_INPUT"



# ------------------------------------
# 🔐 CERTYFIKATY SSL
# ------------------------------------
while IFS= read -r domain || [[ -n "$domain" ]]; do
    domain=$(echo "$domain" | xargs)
    if [[ -z "$domain" ]]; then continue; fi

    echo "🔐 Certyfikat SSL dla $domain"

    # Spróbuj najpierw pełną subdomenę
    cert=$(timeout 5 openssl s_client -servername "$domain" -connect "$domain:443" < /dev/null 2>/dev/null)

    fallback_attempted=false
    fallback_domain=""

    # Jeśli się nie uda, spróbuj dla domeny nadrzędnej (jeśli domena ma 3+ segmenty)
    if [[ -z "$cert" ]]; then
        segment_count=$(echo "$domain" | awk -F'.' '{print NF}')
        if (( segment_count >= 3 )); then
            fallback_domain=$(echo "$domain" | cut -d'.' -f2-)
            echo "🔁 Próba dla nadrzędnej domeny: $fallback_domain"
            cert=$(timeout 5 openssl s_client -servername "$fallback_domain" -connect "$fallback_domain:443" < /dev/null 2>/dev/null)
            fallback_attempted=true
        fi
    fi

    if [[ -z "$cert" ]]; then
        echo -e "Domena: $domain\nBłąd: brak certyfikatu lub połączenia\n----------------------------------------\n" >> "$CERT_OUT"
        continue
    fi

    # Jeśli cert zdobyto przez fallback, nadpisz nazwę domeny do raportu
    final_domain="$domain"
    if [[ "$fallback_attempted" == true && -n "$fallback_domain" && -n "$cert" ]]; then
        final_domain="$fallback_domain"
    fi

    # Parsowanie certyfikatu
    serial=$(echo "$cert" | openssl x509 -noout -serial | cut -d= -f2)
    cn=$(echo "$cert" | openssl x509 -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
    org=$(echo "$cert" | openssl x509 -noout -issuer | sed -n 's/.*O *= *\([^,]*\).*/\1/p')
    not_before=$(echo "$cert" | openssl x509 -noout -startdate | cut -d= -f2)
    not_after=$(echo "$cert" | openssl x509 -noout -enddate | cut -d= -f2)
    sha256=$(echo "$cert" | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)
    sha1=$(echo "$cert" | openssl x509 -noout -fingerprint -sha1 | cut -d= -f2)

    {
        echo "Domena: $final_domain"
        echo "Numer seryjny: $serial"
        echo "Wystawiony przez:"
        echo "Nazwa pospolita (CN): $cn"
        echo "Organizacja (O): $org"
        echo "Okres ważności:"
        echo "Ważny od dnia: $not_before"
        echo "Wygasa dnia: $not_after"
        echo "Odciski:"
        echo "Odcisk SHA-256: $sha256"
        echo "Odcisk SHA1: $sha1"
        echo -e "----------------------------------------\n"
    } >> "$CERT_OUT"
done < "$CERT_INPUT"

echo "✅ Gotowe! Wyniki zapisane w $WHOIS_OUT i $CERT_OUT"
