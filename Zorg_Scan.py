import whois
import dns.resolver
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout
from bs4 import BeautifulSoup
import tldextract
import re
import socket
import http.client
from urllib.parse import urljoin
from tabulate import tabulate
from colorama import init, Fore, Style
import urllib.parse
import urllib3
import ssl
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_website(url):
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════╗")
    print("║", " " * 12, Fore.YELLOW + "ZorgScan By Anonymous Antipedofilia", " " * 12, Fore.CYAN + "║")
    print("╚══════════════════════════════════════════════════════╝" + Style.RESET_ALL)
                                 
    # Verifica il protocollo del sito (HTTP o HTTPS)
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    # Aggiungi l'header User-Agent alla richiesta
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    
    # Effettua la richiesta HTTP/HTTPS per ottenere il contenuto della pagina
    response = requests.get(url, headers=headers, verify=False, timeout=10)
    if response.status_code == 200:
        # Analizza l'HTML della pagina
        soup = BeautifulSoup(response.content, 'html.parser')

        # Trova gli elementi di interesse nel DOM
        # ...
        
        # Esegui la ricerca del registrar
        parsed_url = tldextract.extract(url)
        domain = parsed_url.domain + '.' + parsed_url.suffix
        registrar = get_registrar(domain)
        registrar, registrar_email = get_registrar(domain)

        # Ottieni il tipo di server web utilizzato
        server_type = get_server_type(response.headers)
        
        # Ottieni l'indirizzo IP del sito web
        ip_address = get_ip_address(url)
    
        # Cerca pagine di login
        login_pages = find_login_pages(soup)

        # Cerca pagine di accesso amministrativo
        admin_login_pages = find_admin_login_pages(soup)

        # Trova le email associate al sito web
        emails = find_emails(response.text)
        
        # Trova il file robots.txt
        robots_txt_url = find_robots_txt(url)
        robots_txt_content = get_robots_txt_content(robots_txt_url) if robots_txt_url else "File robots.txt non trovato"

        # Rileva se il sito utilizza Cloudflare
        is_cloudflare = detect_cloudflare(url)

        # Ricerca dei sottodomini
        subdomains = find_subdomains(domain)
        
        # Trova i numeri di telefono associati al sito web
        phone_numbers = find_international_phone_numbers(response.text)

        # Creazione della tabella per l'output
        table = [
            ["URL", url],
            ["Tipo di server web", server_type],
            ["Indirizzo IP", ip_address],
            ["Pagine di login", "\n".join(login_pages) if login_pages else "Nessuna pagina di login trovata"],
            ["Pagine di accesso amministrativo", "\n".join(admin_login_pages) if admin_login_pages else "Nessuna pagina di accesso amministrativo trovata"],
            ["Email", "\n".join(emails) if emails else "Nessuna email trovata"],
            ["Numeri di telefono", "\n".join(phone_numbers) if phone_numbers else "Nessun numero di telefono trovato"],
            ["File robots.txt", robots_txt_content],
            ["Cloudflare", "Sì" if is_cloudflare else "No"],
            ["Registrar", registrar],
            ["Email del registrar", registrar_email if registrar_email else "Nessuna email del registrar trovata"],
            ["Sottodomini", "\n".join(subdomains) if subdomains else "Nessun sottodominio trovato"]
        ]

        # Stampa la tabella
        print(tabulate(table, headers=["Informazioni", "Dettagli"], tablefmt="fancy_grid"))
    else:
        print("Errore durante la richiesta HTTP:", response.status_code)


def get_registrar(domain):
    try:
        whois_info = whois.whois(domain)
        registrar = whois_info.registrar
        registrar_email = whois_info.emails
        return registrar, registrar_email
    except Exception as e:
        return "Impossibile ottenere il registrar"


def get_server_type(headers):
    server_header = headers.get('Server')
    if server_header:
        return server_header
    return "Non disponibile"


def get_ip_address(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return "Impossibile ottenere l'indirizzo IP"


def find_login_pages(soup):
    login_pages = []

    # Analizza tutti i tag 'a' nel DOM e controlla se contengono parole chiave
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            # Aggiungi altre parole chiave se necessario
            if 'login' in href or 'signin' in href or 'log-in' in href or 'sign-in' in href:
                login_pages.append(href)

    # Analizza tutte le form nel DOM e controlla se contengono campi di input per la login
    for form in soup.find_all('form'):
        has_login_inputs = False
        for input_field in form.find_all('input'):
            input_type = input_field.get('type')
            if input_type and input_type.lower() in ['text', 'email', 'username', 'password']:
                has_login_inputs = True
                break
        if has_login_inputs:
            action = form.get('action')
            if action:
                login_pages.append(action)

    return login_pages


def find_admin_login_pages(soup):
    admin_login_pages = []

    # Lista delle parole chiave per la ricerca delle pagine di accesso amministrativo
    admin_keywords = ['admin', 'administrator', 'login', 'signin', 'controlpanel', 'cp', 'dashboard']

    # Analizza tutti i tag 'a' nel DOM e controlla se l'URL contiene parole chiave
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            parsed_url = urllib.parse.urlparse(href)
            path = parsed_url.path.lower()
            if any(keyword in path for keyword in admin_keywords):
                admin_login_pages.append(href)

    # Analizza tutte le form nel DOM e controlla se l'URL dell'azione contiene parole chiave
    for form in soup.find_all('form'):
        action = form.get('action')
        if action:
            parsed_url = urllib.parse.urlparse(action)
            path = parsed_url.path.lower()
            if any(keyword in path for keyword in admin_keywords):
                admin_login_pages.append(action)

    return admin_login_pages


def find_emails(text):
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    return emails


def find_robots_txt(url):
    robots_txt_url = urljoin(url, "/robots.txt")
    response = requests.get(robots_txt_url, verify=False, timeout=10)
    if response.status_code == 200:
        return robots_txt_url
    return None


def get_robots_txt_content(robots_txt_url):
    response = requests.get(robots_txt_url, verify=False, timeout=10)
    if response.status_code == 200:
        return response.text
    return "Impossibile ottenere il contenuto di robots.txt"


def detect_cloudflare(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        ip_address = socket.gethostbyname(hostname)
        conn = http.client.HTTPSConnection(ip_address, context=ssl._create_unverified_context())
        conn.request("GET", "/", headers={"Host": hostname})
        res = conn.getresponse()
        headers = res.getheaders()
        for header in headers:
            if header[0].lower() == "server" and "cloudflare" in header[1].lower():
                return True
        return False
    except Exception as e:
        return False


def find_subdomains(domain):
    subdomains = []
    try:
       answers = dns.resolver.resolve(domain, 'NS')
       for answer in answers:
           subdomain = str(answer).rstrip('.')
           subdomains.append(subdomain)
    except dns.resolver.NXDOMAIN:
       pass

    return subdomains


def find_international_phone_numbers(text):
    # Formato dei numeri di telefono per alcuni paesi comuni
    # Puoi estendere questa lista con più formati per altri paesi
    phone_formats = {
        'US': r'\+\d{1,2}\s?\(\d{3}\)\s?\d{3}\-\d{4}',
        'UK': r'\+\d{2}\s?\d{4}\s?\d{4}',
        'AU': r'\+\d{2}\s?\d{4}\s?\d{4}',
        'DE': r'\+\d{2}\s?\d{3}\s?\d{4}\s?\d{4}',
        'JP': r'\+\d{2}\s?\d{4}\s?\d{4}\s?\d{4}',
        'IT': r'\+\d{2}\s?\d{4}\s?\d{4}\s?\d{4}',
        'RU': r'\+\d{2}\s?\d{4}\s?\d{4}\s?\d{4}',
        # Aggiungi più formati per altri paesi
    }

    phone_numbers = []
    for country, regex_pattern in phone_formats.items():
        matches = re.findall(regex_pattern, text)
        phone_numbers.extend(matches)

    return phone_numbers
       
    
# Esempio di utilizzo
url = input("Inserisci l'URL del sito web da scansionare: ")
scan_website(url)
