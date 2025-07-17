#!/bin/bash

INPUT="whois_cert/domeny.txt"
WHOIS_OUT="whois_cert/whois.txt"
CERT_OUT="whois_cert/certyfikaty.txt"

# Wyczyść stare pliki wynikowe
> "$WHOIS_OUT"
> "$CERT_OUT"

while IFS= read -r domain || [[ -n "$domain" ]]; do
    domain=$(echo "$domain" | xargs) # usuwa spacje

    if [[ -z "$domain" ]]; then
        continue
    fi

    echo "🌐 WHOIS dla $domain"
    response=$(curl -s --max-time 10 "https://api.whois.vu/?q=$domain")

    # Rozkoduj dane WHOIS z JSON – przekształć znaki \r\n, \t, \" na normalne
    whois_text=$(echo "$response" | jq -r '.whois // empty' | sed 's/\\r\\n/\n/g; s/\\n/\n/g; s/\\t/\t/g; s/\\"/"/g')

    if [[ -z "$whois_text" ]]; then
        echo -e "Domena: $domain\nBłąd: brak danych WHOIS – możliwe że API nie obsługuje tej końcówki lub wystąpił limit\n----------------------------------------\n" >> "$WHOIS_OUT"
    else
        {
            echo "Domena: $domain"
            echo "$whois_text" | awk '/>>>/ {exit} {print}' | sed 's/^[ \t]*//'

            echo -e "----------------------------------------\n"
        } >> "$WHOIS_OUT"
    fi
rhlogistics.com
    # CERT — dane SSL
    echo "🔐 Certyfikat SSL dla $domain"
    cert=$(timeout 5 openssl s_client -servername "$domain" -connect "$domain:443" < /dev/null 2>/dev/null)

    if [[ -z "$cert" ]]; then
        echo -e "Domena: $domain\nBłąd: brak certyfikatu lub połączenia\n----------------------------------------\n" >> "$CERT_OUT"
        continue
    fi

    # Parsowanie certyfikatu
    serial=$(echo "$cert" | openssl x509 -noout -serial | cut -d= -f2)

    # CN z Subject
    cn=$(echo "$cert" | openssl x509 -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')

    # O z Issuer (organizacja wystawiająca)
    org=$(echo "$cert" | openssl x509 -noout -issuer | sed -n 's/.*O *= *\([^,]*\).*/\1/p')

    cn=${cn:-"(brak danych)"}
    org=${org:-"(brak danych)"}

    not_before=$(echo "$cert" | openssl x509 -noout -startdate | cut -d= -f2)
    not_after=$(echo "$cert" | openssl x509 -noout -enddate | cut -d= -f2)

    sha256=$(echo "$cert" | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)
    sha1=$(echo "$cert" | openssl x509 -noout -fingerprint -sha1 | cut -d= -f2)

    {
        echo "Numer seryjny $serial"
        echo "Wystawiony przez"
        echo "Nazwa pospolita (CN) $cn"
        echo "Organizacja (O) $org"
        echo "Okres ważności"
        echo "Ważny od dnia $not_before"
        echo "Wygasa dnia $not_after"
        echo "Odciski"
        echo "Odcisk SHA-256 $sha256"
        echo "Odcisk SHA1 $sha1"
        echo -e "----------------------------------------\n"
    } >> "$CERT_OUT"

done < "$INPUT"

echo "✅ Gotowe! Wyniki zapisane w $WHOIS_OUT i $CERT_OUT"
