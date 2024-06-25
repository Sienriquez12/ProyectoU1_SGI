from scapy.all import sniff
from .detect_scan import detect_port_scan
from .ip_utils import get_ip

# Dirección IP de tu máquina
MY_IP = get_ip()
print(MY_IP)
if not MY_IP:
    print("No se pudo obtener la dirección IP. Terminando el programa.")
    exit(1)

# Función principal para iniciar la detección de escaneo de puertos
def start_port_scanner_detection():
    print("Iniciando la detección de escaneo de puertos...")
    # Captura paquetes TCP entrantes hacia tu IP
    sniff(filter=f"tcp and dst host {MY_IP}", prn=detect_port_scan, store=0)
    # Al terminar la detección
    print("\nDetección de escaneo de puertos finalizada.")
