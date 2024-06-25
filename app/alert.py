from .email_sender import send_email_and_whatsapp

# Función para alertar al usuario sobre el posible ataque
def alert_user(attacker_ip):
    print(f"ALERTA: Posible ataque detectado desde {attacker_ip}")
    send_email_and_whatsapp(attacker_ip)  # Enviar correo y WhatsApp
