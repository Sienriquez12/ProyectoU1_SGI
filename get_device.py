import nmap

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

if __name__ == "__main__":
    ip_address = input("Introduce la dirección IP del dispositivo: ")
    info = scan_ip(ip_address)
    if isinstance(info, dict):
        print("Información del dispositivo:")
        print(f"IP: {info['ip']}")
        print(f"Nombre del dispositivo: {info['hostname']}")
        print(f"Sistema operativo: {info['os']}")
        print(f"Dirección MAC: {info['mac']}")
        print(f"Vendedor: {info['vendor']}")
        if info['open_ports']:
            print("Puertos abiertos:")
            for port in info['open_ports']:
                print(f"  - Puerto: {port['port']}, Estado: {port['state']}, Servicio: {port['name']}, Producto: {port['product']}, Versión: {port['version']}")
        else:
            print("No se encontraron puertos abiertos.")
    else:
        print(info)
