import os
from dotenv import load_dotenv
from twilio.rest import Client

load_dotenv()

account_sid = os.getenv('account_sid')
auth_token = os.getenv('auth_token')
from_whatsapp_number = os.getenv('from_whatsapp_number')
to_whatsapp_number = os.getenv('to_whatsapp_number')

# Crear el cliente de Twilio
client = Client(account_sid, auth_token)

# Enviar un mensaje de WhatsApp
message = client.messages.create(
    body='Hola, este es un mensaje de prueba desde Twilio usando Python y dotenv!',
    from_=from_whatsapp_number,
    to=to_whatsapp_number
)

print(f'Mensaje enviado con SID: {message.sid}')
