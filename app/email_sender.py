import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv
from twilio.rest import Client

# Carga las variables de entorno desde el archivo .env
load_dotenv()

# Dirección de correo electrónico del remitente
email_sender = os.getenv('SENDER')
# Contraseña del remitente obtenida de las variables de entorno
password = os.getenv('PASSWORD')
# Dirección de correo electrónico del destinatario
email_reciver = "appatino@espe.edu.ec"

# Variables de entorno para Twilio
account_sid = os.getenv('account_sid')
auth_token = os.getenv('auth_token')
from_whatsapp_number = os.getenv('from_whatsapp_number')
to_whatsapp_number = os.getenv('to_whatsapp_number')

# Función para enviar un correo electrónico y un mensaje de WhatsApp
def send_email_and_whatsapp(ip_src):
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
    em["From"] = email_sender
    em["To"] = email_reciver
    em["Subject"] = subject
    em.set_content(body, subtype="html")

    try:
        # Conecta con el servidor SMTP de Gmail
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(email_sender, password)
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

    # Enviar mensaje de WhatsApp
    client = Client(account_sid, auth_token)
    try:
        message = client.messages.create(
            body=f"⚠️ Alerta de Seguridad: Escaneo de Puertos Detectado desde IP: {ip_src} ⚠️",
            from_=from_whatsapp_number,
            to=to_whatsapp_number
        )
        print(f"Mensaje de WhatsApp enviado con SID: {message.sid}")
    except Exception as e:
        print(f"Ocurrió un error al enviar el mensaje de WhatsApp: {e}")
