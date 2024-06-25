# app/ip_utils.py
import socket

# Función para obtener la dirección IP de la máquina
def get_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as err:
        print(f"No se pudo obtener la dirección IP. Error: {err}")
        return None