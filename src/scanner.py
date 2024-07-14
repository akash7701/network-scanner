import socket

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            try:
                s.send(b'HEAD / HTTP/1.1\r\n\r\n')
                banner = s.recv(1024).decode().strip()
            except:
                banner = "Unknown service"
            return True, banner
    except:
        return False, ""

def scan_network(ip_list, port_list):
    open_ports = {}
    for ip in ip_list:
        open_ports[ip] = []
        print(f"Scanning {ip}...")
        for port in port_list:
            is_open, banner = scan_port(ip, port)
            if is_open:
                print(f"Found open port: {port} - {banner}")
                open_ports[ip].append((port, banner))
    return open_ports

