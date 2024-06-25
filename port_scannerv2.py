import threading
import sys
import time
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
import nmap
from .ip_utils import get_ip
from .email_sender import send_email_and_whatsapp

# Dirección IP de tu máquina
MY_IP = get_ip()
print(MY_IP)
if not MY_IP:
    print("No se pudo obtener la dirección IP. Terminando el programa.")
    exit(1)

# Conjunto para asegurar que el correo se envíe solo una vez por IP
sent_emails = set()
# Bloqueo para sincronizar el acceso al conjunto sent_emails
sent_emails_lock = threading.Lock()

# Variable para contar los paquetes de escaneo detectados
scan_detected_count = 0

# Función para obtener información del dispositivo
def scan_ip(ip_address):
    nm = nmap.PortScanner()
    try:
        # Realiza un escaneo de la IP dada
        nm.scan(ip_address, arguments='-O')  # -O habilita la detección del sistema operativo

        if ip_address not in nm.all_hosts():
            return f"No se encontró el host {ip_address}."

        host_info = nm[ip_address]

        device_info = {
            "ip": ip_address,
            "hostname": "Desconocido",
            "os": "No se pudo determinar el SO",
            "mac": None,
            "vendor": None,
            "open_ports": []
        }

        # Obtiene el nombre del host
        if 'hostnames' in host_info and len(host_info['hostnames']) > 0:
            device_info["hostname"] = host_info['hostnames'][0]['name']

        # Obtiene la información del sistema operativo
        if 'osclass' in host_info:
            for osclass in host_info['osclass']:
                device_info["os"] = osclass['osfamily']
                break

        # Intenta obtener la dirección MAC y el vendedor
        if 'addresses' in host_info and 'mac' in host_info['addresses']:
            device_info["mac"] = host_info['addresses']['mac']
        if 'vendor' in host_info and len(host_info['vendor']) > 0:
            device_info["vendor"] = list(host_info['vendor'].values())[0]

        # Obtiene los puertos abiertos
        if 'tcp' in host_info:
            for port in host_info['tcp']:
                port_info = host_info['tcp'][port]
                device_info["open_ports"].append({
                    "port": port,
                    "state": port_info['state'],
                    "name": port_info['name'],
                    "product": port_info['product'],
                    "version": port_info['version']
                })

        return device_info
    except Exception as e:
        return f"Se produjo un error durante el escaneo: {e}"

# Función para detectar un escaneo de puertos
def detect_port_scan(packet):
    global scan_detected_count
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[IP].dst == MY_IP:
            # Verifica si el paquete tiene solo el flag SYN activado
            if packet[TCP].flags == "S":
                ip_src = packet[IP].src
                tcp_dport = packet[TCP].dport
                print(f"Posible escaneo de puertos detectado desde IP: {ip_src} en el puerto: {tcp_dport}")
                with sent_emails_lock:
                    if ip_src not in sent_emails:
                        sent_emails.add(ip_src)
                        send_email_and_whatsapp(ip_src)  # Enviar correo y WhatsApp
                        scan_detected_count += 1
                        update_progress(scan_detected_count)

                        # Obtener información del dispositivo
                        device_info = scan_ip(ip_src)
                        if isinstance(device_info, dict):
                            print("Información del dispositivo:")
                            print(f"IP: {device_info['ip']}")
                            print(f"Nombre del dispositivo: {device_info['hostname']}")
                            print(f"Sistema operativo: {device_info['os']}")
                            print(f"Dirección MAC: {device_info['mac']}")
                            print(f"Vendedor: {device_info['vendor']}")
                            if device_info['open_ports']:
                                print("Puertos abiertos:")
                                for port in device_info['open_ports']:
                                    print(f"  - Puerto: {port['port']}, Estado: {port['state']}, Servicio: {port['name']}, Producto: {port['product']}, Versión: {port['version']}")
                            else:
                                print("No se encontraron puertos abiertos.")
                        else:
                            print(device_info)

# Función para actualizar la barra de carga
def update_progress(count):
    sys.stdout.write(f"\rDetección en progreso... Paquetes de escaneo detectados: {count}")
    sys.stdout.flush()

# Función principal para iniciar la detección de escaneo de puertos
def start_port_scanner_detection():
    print("Iniciando la detección de escaneo de puertos...")
    # Captura paquetes TCP entrantes hacia tu IP
    sniff(filter=f"tcp and dst host {MY_IP}", prn=detect_port_scan, store=0)

    # Al terminar la detección
    print("\nDetección de escaneo de puertos finalizada.")
    
    
