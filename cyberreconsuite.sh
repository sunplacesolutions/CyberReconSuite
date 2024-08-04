#!/bin/bash

# Verificar si las herramientas están instaladas y mostrar mensaje si falta alguna
check_tool() {
    command -v "$1" >/dev/null 2>&1 || { echo -e "\033[1;31m\033[1mLa herramienta $1 no está instalada. Por favor, instálala primero.\033[0m"; missing_tools+=("$1"); }
}

# Lista de herramientas necesarias
tools=("assetfinder" "httprobe" "subzy" "nikto" "sublist3r" "python3" "dirb" "gobuster" "masscan" "hashcat" "fzf")

# Lista para almacenar herramientas faltantes
missing_tools=()

# Verificar todas las herramientas necesarias
for tool in "${tools[@]}"; do
    check_tool "$tool"
done

# Verificar si falta alguna herramienta
if [ ${#missing_tools[@]} -gt 0 ]; then
    echo -e "\033[1;31m\033[1mAlgunas herramientas faltantes: ${missing_tools[*]}\033[0m"
    echo -e "\033[1;31m\033[1mLas opciones que requieran estas herramientas no funcionarán.\033[0m"
fi

# Función para imprimir el banner
print_banner() {
cat << "EOF"

   ______      __              ____                           _____       _ __     
  / ____/_  __/ /_  ___  _____/ __ \___  _________  ____     / ___/__  __(_) /____ 
 / /   / / / / __ \/ _ \/ ___/ /_/ / _ \/ ___/ __ \/ __ \    \__ \/ / / / / __/ _ \
/ /___/ /_/ / /_/ /  __/ /  / _, _/  __/ /__/ /_/ / / / /   ___/ / /_/ / / /_/  __/
/____/\__, /_.___/\___/_/  /_/ |_|\___/\___/\____/_/ /_/   /____/\__,_/_/\__/\___/ 
    /____/                                                                       
    
EOF
}

# Función para mostrar mensaje de bienvenida y cargar módulos
print_welcome_message() {
    echo -e "\033[1;34m! Bienvenidos a CyberRecon Suite by SunplaceSolutions - Cargando Módulos !\033[0m"
}

# Función para obtener las direcciones IP LAN y WAN
get_ip_addresses() {
    local lan_ip=$(hostname -I | awk '{print $1}')
    local wan_ip=$(curl -s http://api.ipify.org)
    
    echo -e "\033[1;31mDirección IP LAN:\033[0m $lan_ip"
    echo -e "\033[1;31mDirección IP WAN:\033[0m $wan_ip"
}

# Función para mostrar la IP en verde
print_green_ip() {
    local ip_address=$(host "$1" | awk '/has address/ {print $4}')
    echo -e "\033[0;32mIP Address: $ip_address\033[0m"
}

# Función para verificar la vulnerabilidad de transferencia de zona
check_zone_transfer_vulnerability() {
    local domain="$1"

    # Realizar la verificación utilizando dnsrecon
    result=$(dnsrecon -d "$domain" -t axfr 2>&1)

    # Verificar si la transferencia de zona fue denegada
    if echo "$result" | grep -q "Transfer failed"; then
        echo "El dominio $domain NO es vulnerable a la transferencia de zona."
    else
        echo "El dominio $domain ES VULNERABLE a la transferencia de zona."
    fi
}

# Función para obtener la geolocalización de una IP
get_geolocation() {
    local ip_address="$1"
    local geolocation=$(curl -s "http://ip-api.com/json/$ip_address")
    local status=$(echo "$geolocation" | jq -r '.status')
    
    if [ "$status" == "success" ]; then
        local country=$(echo "$geolocation" | jq -r '.country')
        local region=$(echo "$geolocation" | jq -r '.regionName')
        local city=$(echo "$geolocation" | jq -r '.city')
        echo -e "\033[0;32mGeolocation:\033[0m"
        echo -e "\033[0;32mCountry: $country\033[0m"
        echo -e "\033[0;32mRegion: $region\033[0m"
        echo -e "\033[0;32mCity: $city\033[0m"
    else
        echo -e "\033[0;31mFailed to fetch geolocation.\033[0m"
    fi
}

# Función para obtener el nombre DNS de una IP
get_dns_name() {
    local ip_address="$1"
    local dns_name=$(host "$ip_address" | awk '/domain name pointer/ {print $5}')
    
    if [ -n "$dns_name" ]; then
        echo -e "\033[0;32mDNS Name: $dns_name\033[0m"
    else
        echo -e "\033[0;31mNo DNS name found\033[0m"
    fi
}

# Función para obtener el número AS de una IP
get_as_number() {
    local ip_address="$1"
    local as_info=$(whois -h whois.cymru.com " -v $ip_address" | awk 'NR==2 {print $1}')
    
    if [ -n "$as_info" ]; then
        echo -e "\033[0;32mAS Number: $as_info\033[0m"
    else
        echo -e "\033[0;31mNo AS number found\033[0m"
    fi
}

# Función para obtener las tecnologías web utilizando Wappalyzer en Python
get_web_technologies() {
    local url="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 wappalyzer_script.py "$url"
    else
        echo -e "\033[0;31m\033[1mPython3 no está instalado. Por favor, instálalo para utilizar esta función.\033[0m"
    fi
}

# Función para obtener URLs de Wayback Machine
get_waybackurls() {
    local host="$1"
    local with_subs="$2"
    local url
    if [ "$with_subs" == "y" ]; then
        url="http://web.archive.org/cdx/search/cdx?url=*.$host/*&output=txt&collapse=urlkey&fl=original"
    else
        url="http://web.archive.org/cdx/search/cdx?url=$host/*&output=txt&collapse=urlkey&fl=original"
    fi
    local results=$(curl -s "$url")
    
    if [ -n "$results" ]; then
        echo -e "\033[0;35mWayback URLs:\033[0m"
        echo "$results" | awk '{print "\033[1;3" ((NR%6)+1) "m" $0 "\033[0m"}'
    else
        echo -e "\033[0;31mFailed to fetch Wayback URLs or no URLs found.\033[0m"
    fi
}

# Función para mostrar URLs de Wayback Machine y opción para guardar en archivo
waybackurls_command() {
    local host="$1"
    local with_subs="$2"
    local save_option="$3"
    local url
    if [ "$with_subs" == "y" ]; then
        url="http://web.archive.org/cdx/search/cdx?url=*.$host/*&output=txt&collapse=urlkey&fl=original"
    else
        url="http://web.archive.org/cdx/search/cdx?url=$host/*&output=txt&collapse=urlkey&fl=original"
    fi
    local results=$(curl -s "$url")
    
    if [ -n "$results" ]; then
        if [ "$save_option" == "s" ]; then
            echo -e "\033[0;35mWayback URLs:\033[0m"
            echo "$results" | awk '{print "\033[1;3" ((NR%6)+1) "m" $0 "\033[0m"}'
        elif [ "$save_option" == "o" ]; then
            local file_name
            read -p "Ingresa el nombre del archivo para guardar: " file_name
            echo "$results" > "${file_name}.txt"
            echo -e "\033[0;32mResultados guardados en ${file_name}.txt\033[0m"
        fi
    else
        echo -e "\033[0;31mFailed to fetch Wayback URLs or no URLs found.\033[0m"
    fi
}

# Función para buscar dominios en crt.sh
search_crtsh_domain() {
    local domain="$1"
    local save_option="$2"
    local results=$(curl -s "https://crt.sh?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\\*.//g' | sort -u)
    
    if [ -n "$results" ]; then
        if [ "$save_option" == "s" ]; then
            echo -e "\033[0;35mResultados de crt.sh para el dominio $domain:\033[0m"
            echo "$results" | awk '{print "\033[1;3" ((NR%6)+1) "m" $0 "\033[0m"}'
        elif [ "$save_option" == "o" ]; then
            local file_name
            read -p "Ingresa el nombre del archivo para guardar: " file_name
            echo "$results" > "${file_name}.txt"
            echo -e "\033[0;32mResultados guardados en ${file_name}.txt\033[0m"
        fi
    else
        echo -e "\033[0;31mNo se encontraron resultados en crt.sh para el dominio $domain.\033[0m"
    fi
}

# Función para buscar nombres de organización en crt.sh
search_crtsh_org() {
    local org="$1"
    local save_option="$2"
    local results=$(curl -s "https://crt.sh?q=$org&output=json" | jq -r '.[].name_value' | sed 's/\\*.//g' | sort -u)
    
    if [ -n "$results" ]; then
        if [ "$save_option" == "s" ]; then
            echo -e "\033[0;35mResultados de crt.sh para la organización $org:\033[0m"
            echo "$results" | awk '{print "\033[1;3" ((NR%6)+1) "m" $0 "\033[0m"}'
        elif [ "$save_option" == "o" ]; then
            local file_name
            read -p "Ingresa el nombre del archivo para guardar: " file_name
            echo "$results" > "${file_name}.txt"
            echo -e "\033[0;32mResultados guardados en ${file_name}.txt\033[0m"
        fi
    else
        echo -e "\033[0;31mNo se encontraron resultados en crt.sh para la organización $org.\033[0m"
    fi
}

# Función para probar XSS
test_xss() {
    local url_base="$1"
    local payloads=(
        "%22%20onmouseover%3dprompt(31337)%20bad%3d%22"
        "change._change%22%20onmouseover%3dprompt(31337)%20bad%3d%22"
        "45%22%20onmouseover%3dprompt(31337)%20y%3d"
        "\"%20onmouseover%3dprompt(31337)%20y%3d"
        "\"%20onmouseover%3dprompt(alert)%20y%3d"
        "<script>alert('31337')</script>"
    )

    # Leer payloads adicionales de payloads.txt si existe
    if [ -f "payloads.txt" ]; then
        while IFS= read -r line; do
            payloads+=("$line")
        done < "payloads.txt"
    fi

    for payload in "${payloads[@]}"; do
        local test_url="${url_base}${payload}"
        local response=$(curl -s -o /dev/null -w "%{http_code}" "$test_url")

        if [ "$response" == "200" ]; then
            local content=$(curl -s "$test_url")
            if [[ "$content" =~ (alert|31337) ]]; then
                echo -e "\033[0;32m$test_url es vulnerable a XSS!\033[0m"
                echo "$test_url" >> vulnerables.txt
            else
                echo "$test_url" >> no_vulnerables.txt
            fi
        else
            echo -e "\033[0;31mNo se pudo acceder a la URL: $test_url\033[0m"
        fi

        sleep 5
    done
}

# Función para verificar la inyección de cabecera "Host"
check_host_header_injection() {
    local filename="$1"
    local malicious_host="evil.com"

    if [ ! -f "$filename" ]; then
        echo -e "\033[0;31mEl archivo $filename no se encontró. Asegúrese de que el archivo esté en el mismo directorio que el script.\033[0m"
        return
    fi

    local domains=($(cat "$filename"))

    for domain in "${domains[@]}"; do
        local headers=("Host: $malicious_host")
        local response=$(curl -s -w "%{http_code}" -o /dev/null -H "${headers[@]}" "$domain")

        if [ "$response" == "502" ]; then
            echo -e "\033[0;31m$domain - Bad Gateway. The backend server is not responding.\033[0m"
        elif curl -s -H "${headers[@]}" "$domain" | grep -q "$malicious_host"; then
            echo -e "\033[0;34m$domain - Possible Host Header Injection Detected\033[0m"
        else
            echo -e "$domain - No Host Header Injection Detected"
        fi
    done
}

# Función para mostrar cookies
show_cookies() {
    local url="$1"
    local cookies=$(curl -s -I "$url" | grep -i "Set-Cookie")

    if [ -n "$cookies" ]; then
        echo -e "\033[0;35mCookies para $url:\033[0m"
        echo "$cookies"
    else
        echo -e "\033[0;31mNo se encontraron cookies para $url.\033[0m"
    fi
}

# Función para probar inyección en cookies
inject_cookies() {
    local url="$1"
    local payloads=("alert(31337)" "alert(document.cookie)" "1' OR '1'='1" "1 OR 1=1" "<script>alert(31337)</script>")

    # Leer payloads adicionales de payloads.txt si existe
    if [ -f "payloads.txt" ]; then
        while IFS= read -r line; do
            payloads+=("$line")
        done < "payloads.txt"
    fi

    for payload in "${payloads[@]}"; do
        local cookie="test=$payload"
        local response=$(curl -s -o /dev/null -w "%{http_code}" -b "$cookie" "$url")

        if [ "$response" == "200" ]; then
            local content=$(curl -s -b "$cookie" "$url")
            if [[ "$content" =~ (alert|31337) ]]; then
                echo -e "\033[0;32m$payload in $url es vulnerable a XSS o SQLi!\033[0m"
                echo "$payload in $url" >> cookies_vulnerables.txt
            else
                echo "$payload in $url" >> cookies_no_vulnerables.txt
            fi
        else
            echo -e "\033[0;31mNo se pudo acceder a la URL: $url con el payload $payload\033[0m"
        fi

        sleep 5
    done
}

# Función para realizar un escaneo de vulnerabilidades web con Nikto
scan_with_nikto() {
    local url="$1"
    if command -v nikto >/dev/null 2>&1; then
        echo -e "\033[0;35mEscaneando $url con Nikto...\033[0m"
        nikto -h "$url"
    else
        echo -e "\033[0;31m\033[1mNikto no está instalado. Por favor, instálalo para utilizar esta función.\033[0m"
    fi
}

# Función para enumerar subdominios usando Sublist3r
enumerate_subdomains() {
    local domain="$1"
    if command -v sublist3r >/dev/null 2>&1; then
        echo -e "\033[0;35mEnumerando subdominios para $domain...\033[0m"
        sublist3r -d "$domain" -o subdomains.txt
        echo -e "\033[0;32mSubdominios guardados en subdomains.txt\033[0m"
    else
        echo -e "\033[0;31m\033[1mSublist3r no está instalado. Por favor, instálalo para utilizar esta función.\033[0m"
    fi
}

# Función para analizar encabezados HTTP
analyze_http_headers() {
    local url="$1"
    echo -e "\033[0;35mAnalizando encabezados HTTP para $url...\033[0m"
    curl -s -I "$url" | grep -iE "content-security-policy|x-frame-options|x-content-type-options|strict-transport-security"
}

# Función para detectar CMS utilizando Wappalyzer en Python
detect_cms() {
    local url="$1"
    get_web_technologies "$url"
}

# Función para usar assetfinder y httprobe
run_assetfinder_httprobe() {
    local domain="$1"
    if command -v assetfinder >/dev/null 2>&1 && command -v httprobe >/dev/null 2>&1; then
        echo -e "\033[0;35mEjecutando assetfinder y httprobe para $domain...\033[0m"
        local results=$(assetfinder --subs-only "$domain" | httprobe -t 40000)
        
        echo -e "\033[0;35mResultados:\033[0m"
        echo "$results" | awk '{print "\033[1;3" ((NR%6)+1) "m" $0 "\033[0m"}'
        
        read -p "¿Quieres guardar los resultados? (y/n): " save_option
        if [ "$save_option" == "y" ]; then
            read -p "Ingresa el nombre del archivo (o presiona Enter para usar el formato por defecto 'alive_$domain.txt'): " file_name
            file_name=${file_name:-alive_$domain.txt}
            echo "$results" > "$file_name"
            echo -e "\033[0;32mResultados guardados en $file_name\033[0m"
        fi
    else
        echo -e "\033[0;31m\033[1mAssetfinder y/o httprobe no están instalados. Por favor, instálalos para utilizar esta función.\033[0m"
    fi
}

# Función para usar subzy
run_subzy() {
    local filename="$1"
    if command -v subzy >/dev/null 2>&1; then
        echo -e "\033[0;35mEjecutando subzy con los objetivos en $filename...\033[0m"
        subzy -targets "$filename"
    else
        echo -e "\033[0;31m\033[1mSubzy no está instalado. Por favor, instálalo para utilizar esta función.\033[0m"
    fi
}

# Función para enumerar directorios y archivos usando Dirb
enumerate_directories_dirb() {
    local url="$1"
    if command -v dirb >/dev/null 2>&1; then
        echo -e "\033[0;35mEnumerando directorios y archivos en $url con Dirb...\033[0m"
        dirb "$url"
    else
        echo -e "\033[0;31m\033[1mDirb no está instalado. Por favor, instálalo para utilizar esta función.\033[0m"
    fi
}

# Función para enumerar directorios y archivos usando Gobuster
enumerate_directories_gobuster() {
    local url="$1"
    local wordlist="dirlist.txt"
    if command -v gobuster >/dev/null 2>&1; then
        echo -e "\033[0;35mEnumerando directorios y archivos en $url con Gobuster...\033[0m"
        gobuster dir -u "$url" -w "$wordlist"
    else
        echo -e "\033[0;31m\033[1mGobuster no está instalado. Por favor, instálalo para utilizar esta función.\033[0m"
    fi
}

# Función para realizar un escaneo de puertos con Masscan
scan_ports_masscan() {
    local ip_range="$1"
    local ports="$2"
    if command -v masscan >/dev/null 2>&1; then
        echo -e "\033[0;35mEscaneando puertos en $ip_range con Masscan...\033[0m"
        masscan -p"$ports" "$ip_range" --rate=1000
    else
        echo -e "\033[0;31m\033[1mMasscan no está instalado. Por favor, instálalo para utilizar esta función.\033[0m"
    fi
}

# Función para realizar OSINT en redes sociales
perform_osint_social_media() {
    local username="$1"
    echo -e "\033[0;35mRealizando OSINT en redes sociales para el usuario $username...\033[0m"
    # Aquí se podría agregar integración con herramientas OSINT específicas
}

# Función para detectar phishing
detect_phishing() {
    local url="$1"
    echo -e "\033[0;35mVerificando si el dominio $url ha sido reportado por realizar phishing...\033[0m"
    local response=$(curl -s "https://checkphish.ai/api/v1/domain/$url" -H "Authorization: YOUR_API_KEY_HERE")
    echo "$response"
}

# Función para cracking de hashes
crack_hashes() {
    local hash="$1"
    local wordlist="wordlist.txt"
    echo -e "\033[0;35mCracking hash $hash usando wordlist $wordlist...\033[0m"
    hashcat -a 0 -m 0 "$hash" "$wordlist"
}

# Colores del arcoíris para el menú
colors=("\\033[1;31m" "\\033[1;33m" "\\033[1;32m" "\\033[1;36m" "\\033[1;34m" "\\033[1;35m")

# Opciones del menú
options=(
    "Dig"
    "Host"
    "IP"
    "NMap"
    "NmapVuln"
    "nslookup"
    "ping"
    "Status-Viewer"
    "Whois"
    "Geolocalización"
    "Web Technologies"
    "Wayback URLs"
    "crt.sh Domain Search"
    "crt.sh Organization Search"
    "XSS Test"
    "Host Header Injection Test"
    "Show Cookies"
    "Inject Cookies"
    "Nikto Web Scan"
    "Subdomain Enumeration"
    "HTTP Headers Analysis"
    "CMS Detection"
    "Assetfinder + Httprobe"
    "Subzy"
    "Dirb Directory Enumeration"
    "Gobuster Directory Enumeration"
    "Masscan Port Scan"
    "OSINT Social Media"
    "Phishing Detection"
    "Hash Cracking"
    "Salir del Script"
)

while true; do
    clear
    print_banner
    print_welcome_message
    get_ip_addresses

    # Mostrar opciones
    echo -e "\\nOpciones:"
    for ((i=0; i<${#options[@]}; i++)); do
        echo -e "${colors[$((i % ${#colors[@]}))]}$(($i+1))) ${colors[$((i % ${#colors[@]}))]}${options[$i]}\\033[0m"
    done

    echo -e "\033[1;34mIngresa el número de la opción que deseas ejecutar (o 'x' para salir):\033[0m"
    read -p "" option

    case $option in
        1) # Dig
            read -p "Ingresa el dominio que deseas consultar con el comando Dig: " domain
            dig "$domain"
            # Verificar vulnerabilidad de transferencia de zona
            check_zone_transfer_vulnerability "$domain"
            ;;
        2) # Host
            read -p "Ingresa el dominio o la IP que deseas consultar con el comando Host: " domain_or_ip
            host "$domain_or_ip"
            ;;
        3) # IP
            read -p "Ingresa el dominio para mostrar su IP: " domain_to_ip
            print_green_ip "$domain_to_ip"
            ;;
        4) # NMap
            read -p "Ingresa el dominio o la IP que deseas escanear con NMap: " domain_or_ip
            nmap -Pn -p 1-1000 "$domain_or_ip"
            ;;
        5) # NmapVuln
            read -p "Ingresa el dominio o la IP que deseas escanear con NMap (Vulnerabilidades): " domain_or_ip
            nmap -Pn --script vuln -p 1-1000 "$domain_or_ip"
            ;;
        6) # nslookup
            read -p "Ingresa el dominio o la IP que deseas consultar con el comando nslookup: " domain_or_ip
            nslookup "$domain_or_ip"
            ;;
        7) # ping
            read -p "Ingresa el dominio o la IP que deseas hacer ping: " domain_or_ip
            ping -c 4 "$domain_or_ip"
            ;;
        8) # Status-Viewer
            read -p "Ingresa el dominio o la IP para ver el estado del servidor: " address
            ip_address=$(host "$address" | awk '/has address/ {print $4}')
            echo -e "IP Address: \\033[0;32m$ip_address\\033[0m"
            while true; do
                clear
                echo "Implementa la funcionalidad para Status-Viewer aquí"
                # Ejecutar el código para el dominio
                curl_output=$(curl -s -X $'GET' -H $'Host: '$address'' -H $'Accept-Encoding: gzip, deflate' -H $'Accept: */*' -H $'Accept-Language: en-US;q=0.9,en;q=0.8' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36' -H $'Connection: close' -H $'Cache-Control: max-age=0' $'http://'$address'/server-status?full=true' -k --compressed | lynx -stdin -dump)
                echo -e "\\nResultados para $address:"
                echo "$curl_output"
                # Ejecutar el código para la IP si está disponible
                if [[ -n "$ip_address" ]]; then
                    curl_output_ip=$(curl -s -X $'GET' -H $'Host: '$ip_address'' -H $'Accept-Encoding: gzip, deflate' -H $'Accept: */*' -H $'Accept-Language: en-US;q=0.9,en;q=0.8' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36' -H $'Connection: close' -H $'Cache-Control: max-age=0' $'http://'$ip_address'/server-status?full=true' -k --compressed | lynx -stdin -dump)
                    echo -e "\\nResultados para $ip_address:"
                    echo "$curl_output_ip"
                fi
                sleep 10
            done
            ;;
        9) # Whois
            read -p "Ingresa el dominio o la IP que deseas consultar con el comando Whois: " domain_or_ip
            whois "$domain_or_ip"
            ;;
        10) # Geolocalización
            read -p "Ingresa la IP para obtener su geolocalización: " ip_address
            get_geolocation "$ip_address"
            get_dns_name "$ip_address"
            get_as_number "$ip_address"
            ;;
        11) # Web Technologies
            read -p "Ingresa la IP para detectar las tecnologías web: " ip_address
            get_web_technologies "$ip_address"
            ;;
        12) # Wayback URLs
            read -p "Ingresa la dirección IP o el dominio para obtener URLs de Wayback Machine: " host
            read -p "¿Incluir subdominios? (y/n): " with_subs
            read -p "Ingresa 's' para mostrar en pantalla o 'o' para guardar en archivo: " save_option
            waybackurls_command "$host" "$with_subs" "$save_option"
            ;;
        13) # crt.sh Domain Search
            read -p "Ingresa el dominio para buscar en crt.sh: " domain
            read -p "Ingresa 's' para mostrar en pantalla o 'o' para guardar en archivo: " save_option
            search_crtsh_domain "$domain" "$save_option"
            ;;
        14) # crt.sh Organization Search
            read -p "Ingresa el nombre de la organización para buscar en crt.sh: " org
            read -p "Ingresa 's' para mostrar en pantalla o 'o' para guardar en archivo: " save_option
            search_crtsh_org "$org" "$save_option"
            ;;
        15) # XSS Test
            read -p "Ingresa la URL base (Ejemplo: https://www.ejemplo.com/prueba.php?param=): " url_base
            test_xss "$url_base"
            ;;
        16) # Host Header Injection Test
            read -p "Ingresa el nombre del archivo que contiene la lista de dominios: " filename
            check_host_header_injection "$filename"
            ;;
        17) # Show Cookies
            read -p "Ingresa la URL para mostrar las cookies: " url
            show_cookies "$url"
            ;;
        18) # Inject Cookies
            read -p "Ingresa la URL para probar la inyección en cookies: " url
            inject_cookies "$url"
            ;;
        19) # Nikto Web Scan
            read -p "Ingresa la URL para escanear con Nikto: " url
            scan_with_nikto "$url"
            ;;
        20) # Subdomain Enumeration
            read -p "Ingresa el dominio para enumerar subdominios: " domain
            enumerate_subdomains "$domain"
            ;;
        21) # HTTP Headers Analysis
            read -p "Ingresa la URL para analizar los encabezados HTTP: " url
            analyze_http_headers "$url"
            ;;
        22) # CMS Detection
            read -p "Ingresa la URL para detectar el CMS: " url
            detect_cms "$url"
            ;;
        23) # Assetfinder + Httprobe
            read -p "Ingresa el dominio para usar assetfinder y httprobe: " domain
            run_assetfinder_httprobe "$domain"
            ;;
        24) # Subzy
            read -p "Ingresa el nombre del archivo que contiene la lista de objetivos: " filename
            run_subzy "$filename"
            ;;
        25) # Dirb Directory Enumeration
            read -p "Ingresa la URL para enumerar directorios y archivos con Dirb: " url
            enumerate_directories_dirb "$url"
            ;;
        26) # Gobuster Directory Enumeration
            read -p "Ingresa la URL para enumerar directorios y archivos con Gobuster: " url
            enumerate_directories_gobuster "$url"
            ;;
        27) # Masscan Port Scan
            read -p "Ingresa el rango de IP para escanear con Masscan: " ip_range
            read -p "Ingresa los puertos a escanear (Ejemplo: 80,443): " ports
            scan_ports_masscan "$ip_range" "$ports"
            ;;
        28) # OSINT Social Media
            read -p "Ingresa el nombre de usuario para realizar OSINT: " username
            perform_osint_social_media "$username"
            ;;
        29) # Phishing Detection
            read -p "Ingresa la URL para verificar phishing: " url
            detect_phishing "$url"
            ;;
        30) # Hash Cracking
            read -p "Ingresa el hash para crackear: " hash
            crack_hashes "$hash"
            ;;
        0 | x | X) # Salir del Script
            echo "Saliendo del script..."
            exit 0
            ;;
        *) echo "Opción inválida. Por favor, ingresa un número válido de opción.";;
    esac

    read -p "Presiona Enter para continuar..."
done
