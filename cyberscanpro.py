import socket
import subprocess
from datetime import datetime

# Fonction pour trouver l'IP d'un site
def trouver_ip(site):
    try:
        return socket.gethostbyname(site)
    except:
        return None

# Fonction pour tester la connexion (ping)
def tester_ping(ip):
    try:
        result = subprocess.run(['ping', '-c', '3', ip], capture_output=True, text=True)
        return "OK" if "3 received" in result.stdout else "Probleme"
    except:
        return "Erreur"

# Fonction pour scanner un port
def scanner_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    resultat = sock.connect_ex((ip, port))
    sock.close()
    return "OUVERT" if resultat == 0 else "FERME"

# Programme principal
print("=== CYBERSCAN SIMPLE ===")

while True:
    site = input("\nEntrez un site (ou 'quitter'): ")
    if site.lower() == 'quitter':
        break
    
    # Etape 1: Trouver l'IP
    ip = trouver_ip(site)
    if not ip:
        print("Site introuvable!")
        continue
    
    print(f"\nResultats pour {site}:")
    print(f"IP: {ip}")
    
    # Etape 2: Tester le ping
    print(f"Ping: {tester_ping(ip)}")
    
    # Etape 3: Scanner les ports importants
    ports = [80, 443, 22]  # HTTP, HTTPS, SSH
    print("\nPorts:")
    for port in ports:
        print(f"- Port {port}: {scanner_port(ip, port)}")
    
    # Sauvegarder les resultats
    with open(f"rapport_{site}.txt", "w") as f:
        f.write(f"Scan de {site} le {datetime.now()}\n")
        f.write(f"IP: {ip}\n")
        f.write("Ports:\n")
        for port in ports:
            f.write(f"- {port}: {scanner_port(ip, port)}\n")

print("\nScan termine. Les rapports ont ete sauvegardes.")