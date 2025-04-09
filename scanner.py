import tkinter as tk
from tkinter import ttk, messagebox
import argparse
import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
import struct

# Constantes para el escaneo SYN (requiere permisos de root)
try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class NetworkScanner:
    @staticmethod
    def tcp_connect_scan(host, port, timeout=1):
        """Escaneo TCP Connect (estándar, no requiere privilegios)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        except Exception as e:
            print(f"Error en TCP Connect scan: {e}")
            return False

    @staticmethod
    def syn_scan(host, port, timeout=1):
        """Escaneo SYN (requiere permisos de root y scapy)"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy no está instalado. Usando TCP Connect como fallback.")
        
        conf.verb = 0  # Silenciar scapy
        packet = IP(dst=host)/TCP(dport=port, flags="S")
        try:
            response = sr1(packet, timeout=timeout, verbose=0)
            if response and response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Enviamos RST para cerrar la conexión
                    rst_pkt = IP(dst=host)/TCP(dport=port, flags="R")
                    sr1(rst_pkt, timeout=timeout, verbose=0)
                    return True
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return False
            return False
        except Exception as e:
            print(f"Error en SYN scan: {e}")
            return False

    @staticmethod
    def udp_scan(host, port, timeout=1):
        """Escaneo UDP (menos fiable que TCP)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            # Enviamos un paquete vacío (podría ser específico del protocolo)
            sock.sendto(b'', (host, port))
            
            # Intentamos recibir una respuesta
            data, addr = sock.recvfrom(1024)
            return True
        except socket.timeout:
            # Podría estar abierto o filtrando
            return None  # Indeterminado
        except ConnectionRefusedError:
            return False
        except Exception as e:
            print(f"Error en UDP scan: {e}")
            return False
        finally:
            sock.close()

    @staticmethod
    def ping_host(ip, timeout=1):
        """Realiza un ping al host"""
        sistema = platform.system()
        if sistema == "Windows":
            comando = ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip)]
        else:
            comando = ["ping", "-c", "1", "-W", str(timeout), str(ip)]

        resultado = subprocess.run(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return resultado.returncode == 0

    @staticmethod
    def scan_ports(host, ports, scan_type="TCP", timeout=1):
        """Escanea puertos usando el método especificado"""
        open_ports = []
        
        scan_method = {
            "TCP": NetworkScanner.tcp_connect_scan,
            "SYN": NetworkScanner.syn_scan,
            "UDP": NetworkScanner.udp_scan
        }.get(scan_type, NetworkScanner.tcp_connect_scan)

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_method, host, port, timeout): port for port in ports}
            for future in futures:
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    print(f"Error escaneando puerto {port}: {e}")

        return open_ports

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Red Avanzado")
        self.root.geometry("600x500")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Frame de configuración
        config_frame = ttk.LabelFrame(self.root, text="Configuración de Escaneo", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Subred
        ttk.Label(config_frame, text="Subred (ej. 192.168.1.0/24):").grid(row=0, column=0, sticky=tk.W)
        self.entry_subred = ttk.Entry(config_frame, width=30)
        self.entry_subred.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Host individual
        ttk.Label(config_frame, text="Host individual:").grid(row=1, column=0, sticky=tk.W)
        self.entry_host = ttk.Entry(config_frame, width=30)
        self.entry_host.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Puertos
        ttk.Label(config_frame, text="Puertos (ej. 80,443 o 1-100):").grid(row=2, column=0, sticky=tk.W)
        self.entry_ports = ttk.Entry(config_frame, width=30)
        self.entry_ports.grid(row=2, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Tipo de escaneo
        ttk.Label(config_frame, text="Tipo de escaneo:").grid(row=3, column=0, sticky=tk.W)
        self.scan_type = tk.StringVar(value="TCP")
        scan_options = ["TCP", "SYN", "UDP"] if SCAPY_AVAILABLE else ["TCP", "UDP"]
        self.scan_menu = ttk.OptionMenu(config_frame, self.scan_type, "TCP", *scan_options)
        self.scan_menu.grid(row=3, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Opciones adicionales
        self.scan_all = tk.BooleanVar()
        ttk.Checkbutton(config_frame, text="Escanear puertos comunes (1-1024)", variable=self.scan_all).grid(row=4, column=0, columnspan=2, sticky=tk.W)
        
        # Botón de escaneo
        ttk.Button(config_frame, text="Iniciar Escaneo", command=self.start_scan).grid(row=5, column=0, columnspan=2, pady=10)
        
        # Frame de resultados
        result_frame = ttk.LabelFrame(self.root, text="Resultados", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = tk.Text(result_frame, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Barra de estado
        self.status_var = tk.StringVar(value="Listo")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN).pack(fill=tk.X, padx=10, pady=5)
    
    def process_ports(self, port_str):
        """Convierte el string de puertos a una lista de números"""
        ports = set()
        parts = port_str.split(",")
        for part in parts:
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return sorted(ports)
    
    def detect_services(self, ports):
        """Detecta servicios comunes"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
        }
        return {port: common_services.get(port, "Desconocido") for port in ports}
    
    def start_scan(self):
        """Inicia el escaneo según los parámetros configurados"""
        subred = self.entry_subred.get()
        host = self.entry_host.get()
        port_str = self.entry_ports.get()
        scan_type = self.scan_type.get()
        scan_all = self.scan_all.get()
        
        self.result_text.delete(1.0, tk.END)
        self.status_var.set("Escaneando...")
        self.root.update()
        
        try:
            # Escaneo de hosts activos
            if subred:
                self.result_text.insert(tk.END, f"Escaneando subred: {subred}\n")
                active_hosts = self.scan_network(subred)
                self.result_text.insert(tk.END, "\nHosts activos:\n")
                for h in active_hosts:
                    self.result_text.insert(tk.END, f" - {h}\n")
            
            # Escaneo de puertos
            if host:
                if scan_all:
                    ports = list(range(1, 1025))
                elif port_str:
                    ports = self.process_ports(port_str)
                else:
                    messagebox.showwarning("Advertencia", "Debe especificar puertos o seleccionar 'Escanear puertos comunes'")
                    self.status_var.set("Listo")
                    return
                
                self.result_text.insert(tk.END, f"\nEscaneando {scan_type} puertos en {host}...\n")
                open_ports = NetworkScanner.scan_ports(host, ports, scan_type)
                
                if open_ports:
                    services = self.detect_services(open_ports)
                    self.result_text.insert(tk.END, "\nPuertos abiertos:\n")
                    for port in sorted(open_ports):
                        self.result_text.insert(tk.END, f" - Puerto {port}: {services[port]}\n")
                else:
                    self.result_text.insert(tk.END, "\nNo se encontraron puertos abiertos.\n")
            
            self.status_var.set("Escaneo completado")
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error: {str(e)}")
            self.status_var.set("Error")
        finally:
            self.root.update()
    
    def scan_network(self, subnet):
        """Escanea una subred para encontrar hosts activos"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            active_hosts = []
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(NetworkScanner.ping_host, str(host)): host 
                          for host in network.hosts()}
                
                for future in futures:
                    host = futures[future]
                    if future.result():
                        active_hosts.append(str(host))
            
            return active_hosts
        except ValueError as e:
            raise ValueError(f"Subred no válida: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()