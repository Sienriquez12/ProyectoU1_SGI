import subprocess
import platform

# Lista para almacenar IPs bloqueadas
blocked_ips = set()

# Función para bloquear la dirección IP del atacante
def block_attacker(attacker_ip):
    if attacker_ip not in blocked_ips:
        if platform.system() == "Windows":
            # Crear un comando para bloquear la IP usando el firewall de Windows
            cmd = f'netsh advfirewall firewall add rule name="Block {attacker_ip}" dir=in action=block remoteip={attacker_ip}'
        else:
            # Crear un comando para bloquear la IP usando iptables en sistemas Unix
            cmd = f'sudo iptables -A INPUT -s {attacker_ip} -j DROP'

        # Ejecutar el comando
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"IP del atacante bloqueada: {attacker_ip}")  # Confirmar que la IP ha sido bloqueada
            blocked_ips.add(attacker_ip)  # Añadir la IP a la lista de IPs bloqueadas
        else:
            print(f"Fallo al bloquear la IP del atacante: {attacker_ip}")  # Indicar si hubo un error
            print(result.stderr)  # Mostrar el mensaje de error
    else:
        print(f"La IP del atacante {attacker_ip} ya está bloqueada.")  # Informar que la IP ya está bloqueada
