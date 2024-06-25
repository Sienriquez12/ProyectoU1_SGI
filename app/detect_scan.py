import threading
from scapy.layers.inet import TCP, IP
from .alert import alert_user
from .block import block_attacker
from .scan import scan_ip
from .progress import update_progress
from .ip_utils import get_ip

# Dirección IP de tu máquina
MY_IP = get_ip()

# Conjunto para asegurar que el correo se envíe solo una vez por IP
sent_emails = set()
# Bloqueo para sincronizar el acceso al conjunto sent_emails
sent_emails_lock = threading.Lock()

# Variable para contar los paquetes de escaneo detectados
scan_detected_count = 0

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
                        scan_detected_count += 1
                        update_progress(scan_detected_count)
                        
                        # Alertar al usuario y bloquear la IP atacante
                        alert_user(ip_src)
                        block_attacker(ip_src)

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
