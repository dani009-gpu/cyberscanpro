import socket
import subprocess
from datetime import datetime
import time
import os

# Configuration
PORTS = [22, 80, 443, 3306]  # Ports à scanner
SUBDOMAINS = ['mail.', 'admin.', 'ftp.', 'webmail.']  # Sous-domaines à tester
MAX_ATTEMPTS = 3  # Nombre max de tentatives infructueuses

def clear_screen():
    """Efface l'écran du terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_ip(domain):
    """Résout un domaine en adresse IP"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def ping_host(ip):
    """Effectue 3 pings et retourne le taux de réussite"""
    successes = 0
    for _ in range(3):
        try:
            subprocess.check_output(
                ['ping', '-n', '1', ip] if os.name == 'nt' else ['ping', '-c', '1', ip],
                stderr=subprocess.DEVNULL
            )
            successes += 1
            time.sleep(1)  # Délai entre les pings
        except:
            pass
    return f"{successes}/3 ({(successes/3)*100:.0f}%)"

def get_ttl(ip):
    """Récupère le TTL depuis le ping"""
    try:
        output = subprocess.check_output(
            ['ping', '-n', '1', ip] if os.name == 'nt' else ['ping', '-c', '1', ip],
            stderr=subprocess.DEVNULL
        ).decode()
        return int(output.split('TTL=')[1].split('\n')[0])
    except:
        return None

def guess_os(ttl):
    """Devine l'OS basé sur le TTL"""
    if ttl is None:
        return "Inconnu"
    elif ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Autre (peut-être routeur)"

def reverse_dns(ip):
    """Tente une résolution DNS inverse"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Non trouvé"

def scan_port(ip, port):
    """Scan un port et tente de récupérer la bannière"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                try:
                    s.send(b"GET / HTTP/1.1\r\n\r\n")
                    banner = s.recv(1024).decode(errors='ignore').strip()
                    return True, banner.split('\n')[0] if banner else "Pas de bannière"
                except:
                    return True, "Bannière non lisible"
            return False, None
    except:
        return False, None

def check_http(ip):
    """Vérifie la réponse HTTP"""
    return scan_port(ip, 80)[0]

def check_https(ip):
    """Vérifie si HTTPS est actif"""
    return scan_port(ip, 443)[0]

def scan_subdomains(domain):
    """Scan les sous-domaines courants"""
    found = []
    for sub in SUBDOMAINS:
        full_domain = sub + domain
        try:
            socket.gethostbyname(full_domain)
            found.append(full_domain)
        except:
            pass
    return found

def generate_report(domain, data):
    """Génère un rapport dans un fichier"""
    filename = f"rapport_{domain.replace('.', '_')}.txt"
    with open(filename, 'w') as f:
        f.write(f"=== Rapport de scan pour {domain} ===\n")
        f.write(f"Date: {datetime.now()}\n\n")
        for key, value in data.items():
            f.write(f"{key}: {value}\n")
    return filename

def update_history(domain):
    """Met à jour l'historique"""
    with open("historique.txt", "a") as f:
        f.write(f"{datetime.now()} - Scan de {domain}\n")

def show_ports(open_ports):
    """Affiche les ports sous forme ASCII"""
    print("\nPorts:")
    for port in PORTS:
        status = "[OUVERT]" if port in open_ports else "[FERME]"
        print(f"  {port} {status}")

def main():
    clear_screen()
    print("=== CYBERSCAN - Scanner de sécurité ===")
    print("Tapez 'exit' pour quitter\n")
    
    failed_attempts = 0
    
    while True:
        domain = input("Entrez un domaine à analyser: ").strip()
        
        if domain.lower() == 'exit':
            break
            
        if not domain:
            print("Veuillez entrer un domaine valide")
            continue
            
        # Résolution DNS
        ip = get_ip(domain)
        if not ip:
            failed_attempts += 1
            print(f"Erreur: Impossible de résoudre {domain}")
            if failed_attempts >= MAX_ATTEMPTS:
                print("Trop d'échecs - Blocage activé")
                break
            continue
            
        failed_attempts = 0  # Réinitialiser le compteur
        
        # Collecte des données
        data = {
            "Domaine": domain,
            "IP": ip,
            "Ping": ping_host(ip),
            "TTL": get_ttl(ip),
            "OS probable": guess_os(get_ttl(ip)),
            "Nom machine": reverse_dns(ip),
            "HTTP actif": "Oui" if check_http(ip) else "Non",
            "HTTPS actif": "Oui" if check_https(ip) else "Non",
            "Sous-domaines trouvés": ", ".join(scan_subdomains(domain)) or "Aucun"
        }
        
        # Scan des ports
        open_ports = []
        banners = {}
        for port in PORTS:
            is_open, banner = scan_port(ip, port)
            if is_open:
                open_ports.append(port)
                banners[port] = banner
        data["Ports ouverts"] = ", ".join(map(str, open_ports)) or "Aucun"
        
        # Affichage des résultats
        clear_screen()
        print(f"\n=== Résultats pour {domain} ===")
        for key, value in data.items():
            print(f"{key}: {value}")
            
        show_ports(open_ports)
        
        # Bannières
        if banners:
            print("\nBannières:")
            for port, banner in banners.items():
                print(f"  Port {port}: {banner[:100]}...")
        
        # Génération des rapports
        report_file = generate_report(domain, data)
        update_history(domain)
        print(f"\nRapport sauvegardé dans {report_file}")
        print("Historique mis à jour dans historique.txt")

if __name__ == "__main__":
    main()
