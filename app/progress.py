import sys

def update_progress(count):
    sys.stdout.write(f"\rDetección en progreso... Paquetes de escaneo detectados: {count}")
    sys.stdout.flush()
