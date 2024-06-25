from scapy.all import sniff
from scapy.layers.inet import TCP, IP
import socket
import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv
import threading

# Función para obtener la dirección IP de la máquina
def get_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as err:
        print(f"No se pudo obtener la dirección IP. Error: {err}")
        return None

# Carga las variables de entorno desde el archivo .env
load_dotenv()

# Dirección de correo electrónico del remitente
email_sender = os.getenv('SENDER')
# Contraseña del remitente obtenida de las variables de entorno
password = os.getenv('PASSWORD')
# Dirección de correo electrónico del destinatario
email_reciver = "appatino@espe.edu.ec"

# Si la contraseña no se ha cargado (es None), detiene la ejecución con un error
if password is None:
    raise ValueError("No se pudo leer la contraseña del archivo .env")

# Conjunto para asegurar que el correo se envíe solo una vez por IP
sent_emails = set()
# Bloqueo para sincronizar el acceso al conjunto sent_emails
sent_emails_lock = threading.Lock()

# Función para enviar un correo electrónico
def send_email(ip_src):
    # Asunto del correo electrónico
    subject = "⚠️ Alerta de Seguridad: Escaneo de Puertos Detectado ⚠️"
    # Cuerpo del correo electrónico en formato HTML
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; text-align: center;">
            <div style="border: 2px solid red; padding: 20px; margin: 20px;">
                <h1 style="color: red;">⚠️ Alerta de Seguridad ⚠️</h1>
                <p style="font-size: 18px;">Se ha detectado un posible escaneo de puertos en tu máquina.</p>
                <p style="font-size: 16px;">Fuente del ataque: <b>{ip_src}</b></p>
                <p style="color: red; font-size: 20px;">¡Podrían estar intentando vulnerar tu sistema!</p>
            </div>
        </body>
    </html>
    """

    # Crea un objeto EmailMessage para configurar los detalles del correo
    em = EmailMessage()
    # Establece el remitente del correo
    em["From"] = email_sender
    # Establece el destinatario del correo
    em["To"] = email_reciver
    # Establece el asunto del correo
    em["Subject"] = subject
    # Establece el cuerpo del correo en formato HTML
    em.set_content(body, subtype="html")

    # Intenta enviar el correo y maneja posibles excepciones
    try:
        # Conecta con el servidor SMTP de Gmail
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            # Inicia sesión en el servidor SMTP
            smtp.login(email_sender, password)
            # Envía el correo
            smtp.send_message(em)
            print("Correo enviado exitosamente")

    except smtplib.SMTPAuthenticationError:
        print("Error de autenticación: Verifique su usuario y contraseña.")
    except smtplib.SMTPRecipientsRefused:
        print("Error: El destinatario ha sido rechazado por el servidor.")
    except smtplib.SMTPException as e:
        print(f"Error al enviar el correo: {e}")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")

# Dirección IP de tu máquina
MY_IP = get_ip()
if MY_IP:
    print(f"Tu dirección IP es: {MY_IP}")
else:
    print("No se pudo obtener la dirección IP. Terminando el programa.")
    exit(1)

# Función para detectar un escaneo de puertos
def detect_port_scan(packet):
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
                        send_email(ip_src)

# Función principal
def main():
    print("Iniciando la detección de escaneo de puertos...")
    # Captura paquetes TCP entrantes hacia tu IP
    sniff(filter=f"tcp and dst host {MY_IP}", prn=detect_port_scan, store=0)

if __name__ == "__main__":
    main()