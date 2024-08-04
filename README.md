# CyberRecon Suite

## Descripción

CyberRecon Suite es una herramienta integral para realizar diversas tareas de reconocimiento y pruebas de seguridad en redes y aplicaciones web. Incluye funciones para escaneo de puertos, enumeración de subdominios, detección de CMS, pruebas de inyección, y mucho más. Esta suite está diseñada para facilitar el trabajo de los profesionales de ciberseguridad proporcionando un conjunto unificado de comandos y opciones.

## Funcionalidades

- **Dig**: Consulta DNS con el comando `dig`.
- **Host**: Consulta DNS con el comando `host`.
- **IP**: Muestra la dirección IP de un dominio.
- **NMap**: Escanea puertos con `nmap`.
- **NmapVuln**: Escanea vulnerabilidades con `nmap`.
- **nslookup**: Consulta DNS con el comando `nslookup`.
- **ping**: Realiza ping a un dominio o IP.
- **Status-Viewer**: Muestra el estado del servidor.
- **Whois**: Realiza consultas `whois`.
- **Geolocalización**: Muestra la geolocalización de una IP.
- **Web Technologies**: Detecta tecnologías web utilizando Wappalyzer en Python.
- **Wayback URLs**: Obtiene URLs archivadas en Wayback Machine.
- **crt.sh Domain Search**: Busca certificados de dominio en crt.sh.
- **crt.sh Organization Search**: Busca certificados de organización en crt.sh.
- **XSS Test**: Prueba vulnerabilidades XSS.
- **Host Header Injection Test**: Prueba inyección de cabeceras `Host`.
- **Show Cookies**: Muestra las cookies de un sitio web.
- **Inject Cookies**: Prueba inyección en cookies.
- **Nikto Web Scan**: Escanea vulnerabilidades web con Nikto.
- **Subdomain Enumeration**: Enumera subdominios usando Sublist3r.
- **HTTP Headers Analysis**: Analiza encabezados HTTP.
- **CMS Detection**: Detecta CMS utilizando Wappalyzer en Python.
- **Assetfinder + Httprobe**: Encuentra y prueba subdominios vivos.
- **Subzy**: Detecta subdominios tomados.
- **Dirb Directory Enumeration**: Enumera directorios y archivos con Dirb.
- **Gobuster Directory Enumeration**: Enumera directorios y archivos con Gobuster.
- **Masscan Port Scan**: Escanea puertos con Masscan.
- **OSINT Social Media**: Realiza OSINT en redes sociales.
- **Phishing Detection**: Verifica si un dominio ha sido reportado por realizar phishing.
- **Hash Cracking**: Cracking de hashes utilizando `hashcat`.

## Requisitos

### Librerías de Python

## Asegúrate de tener instaladas las siguientes librerías de Python:
pip install requests colorama

## Para la funcionalidad de detección de CMS utilizando Wappalyzer:
pip install python-Wappalyzer

## Herramientas adicionales
Las siguientes herramientas deben estar instaladas en tu sistema:

## assetfinder
## httprobe
## subzy
## nikto
## sublist3r
## python3
## dirb
## gobuster
## masscan
## hashcat

## Instalación de herramientas adicionales

# Instalar assetfinder
go get -u github.com/tomnomnom/assetfinder

# Instalar httprobe
go get -u github.com/tomnomnom/httprobe

# Instalar subzy
go get -u github.com/lukasikic/subzy

# Instalar nikto
sudo apt-get install nikto

# Instalar sublist3r
pip install sublist3r

# Instalar dirb
sudo apt-get install dirb

# Instalar gobuster
go get -u github.com/OJ/gobuster

# Instalar masscan
sudo apt-get install masscan

# Instalar hashcat
sudo apt-get install hashcat

## USO
chmod +x cyberreconsuite.sh
./cyberreconsuite.sh

## Contribuir
## Si deseas contribuir a este proyecto, por favor realiza un fork del repositorio y envía un pull request con tus mejoras. Agradecemos cualquier aporte para mejorar esta herramienta.

## Licencia
## Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.
