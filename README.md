# DDoS-Monitor – Echtzeit-Erkennung von SYN, UDP & TCP Attacken

Dieses Skript überwacht in Echtzeit den Netzwerkverkehr eines Servers und erkennt potenzielle DDoS-Angriffe. Es identifiziert spezifische Protokolle (TCP, UDP) und relevante TCP-Flags (SYN, RST, FIN, ACK) sowie Spoofed IPs (AMPS). Sobald ein Angriff erkannt wird, wird dies sofort angezeigt. Es hilft, Server vor Überlastung durch schädlichen Datenverkehr zu schützen.

Hauptfunktionen:

- Netzwerkverkehr überwachen:
Das Skript überwacht kontinuierlich den eingehenden Netzwerkverkehr und zeigt die Anzahl der Pakete an, die durch verschiedene Protokolle und TCP-Flags erzeugt werden.
Es wird für jedes Paket überprüft, ob es sich um ein TCP-, UDP- oder Spoofed-IP handelt.

- Protokollerkennung:
- TCP-Protokolle: Das Skript zählt Pakete mit den TCP-Flags SYN, RST, FIN und ACK.
- UDP-Protokolle: UDP-Pakete werden ebenfalls gezählt.
- Spoofed IPs (AMPS): Es wird geprüft, ob die Quelle des Pakets eine verdächtige, nicht-private IP-Adresse (möglicherweise durch Spoofing) verwendet.

- Angriffserkennung:
Ein DDoS-Angriff wird erkannt, wenn mehr als 1000 Pakete pro Sekunde durch den Netzwerkadapter empfangen werden.
Wird dieser Schwellenwert überschritten, wird die Anzeige auf "ATTACK: YES" gesetzt.

- Echtzeit-Anzeige:
Das Skript zeigt in Echtzeit die Anzahl der TCP- und UDP-Pakete sowie die Anzahl der Pakete mit bestimmten TCP-Flags (SYN, RST, FIN, ACK).
Es zeigt die Anzahl der verdächtigen Spoofed IPs (AMPS) und die Gesamtzahl der empfangenen Pakete.
Wenn ein Angriff erkannt wird, wird dies sofort angezeigt.

- Verwendung eines raw Sockets:
Das Skript verwendet Raw Sockets, um alle eingehenden Netzwerkpakete direkt zu erfassen, ohne auf bestimmte Protokolle angewiesen zu sein.

- Interaktive Benutzeroberfläche:
Das Skript gibt während seiner Ausführung ständig ein übersichtliches Banner mit den aktuellen Statistiken aus, um eine kontinuierliche Überwachung zu ermöglichen.
Ein einfaches, textbasiertes Dashboard wird auf der Konsole angezeigt, das die Anzahl der Pakete in Echtzeit anzeigt und sofortiges Feedback zu möglichen Angriffen gibt.

- Kompatibilität:
Das Skript ist unter Linux-basierten Systemen (wie Ubuntu, CentOS, Debian) lauffähig, da es auf Sockets und Netzwerk-APIs zugreift, die spezifisch für Unix-Systeme sind.

## Installation
Das Tool läuft nur unter Linux und benötigt Python 3.11+.  

pip install psutil

## Features
✅ Echtzeit-Erkennung von SYN-Flood-, UDP- und TCP-Angriffen  
✅ Analyse von Spoofed IPs (AMPS)  
✅ Unterstützung für IP-Blacklist & Whitelist  
✅ Optimiert für hohe Netzwerkgeschwindigkeit  

## Tags
`DDoS`, `Network Security`, `Cybersecurity`, `Python`, `Firewall`, `Intrusion Detection`
