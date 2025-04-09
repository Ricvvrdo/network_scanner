import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class NetworkScanner:
    @staticmethod
    def ping_host(ip, timeout=1):
        """Realiza ping a un host"""
        sistema = platform.system()
        param = "-n" if sistema == "Windows" else "-c"
        timeout_param = "-w" if sistema == "Windows" else "-W"
        timeout_val = str(timeout * 1000) if sistema == "Windows" else str(timeout)
        
        command = ["ping", param, "1", timeout_param, timeout_val, ip]
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, timeout=timeout+1)
            return output.returncode == 0
        except:
            return False

    @staticmethod
    def scan_network(subnet):
        """Escanea una subred para hosts activos"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            active_hosts = []
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(NetworkScanner.ping_host, str(host)): host 
                          for host in network.hosts()}
                
                for future in as_completed(futures):
                    host = futures[future]
                    if future.result():
                        active_hosts.append(str(host))
            
            return active_hosts
        except ValueError as e:
            raise ValueError(f"Subred no válida: {str(e)}")

    @staticmethod
    def tcp_connect_scan(host, port, timeout=1):
        """Escaneo TCP Connect (estándar)"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception as e:
            print(f"Error TCP Connect en puerto {port}: {e}")
            return False

    @staticmethod
    def syn_scan(host, port, timeout=1):
        """Escaneo SYN (requiere scapy y permisos root)"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy no está instalado")
        
        conf.verb = 0
        try:
            pkt = IP(dst=host)/TCP(dport=port, flags="S")
            response = sr1(pkt, timeout=timeout, verbose=0)
            
            if response is None:
                return False
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Enviamos RST para cerrar
                    sr1(IP(dst=host)/TCP(dport=port, flags="R"), 
                        timeout=timeout, verbose=0)
                    return True
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return False
            return False
        except Exception as e:
            print(f"Error SYN scan en puerto {port}: {e}")
            return False

    @staticmethod
    def udp_scan(host, port, timeout=1):
        """Escaneo UDP (menos fiable)"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(b'', (host, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    return True
                except socket.timeout:
                    # Posiblemente abierto o filtrado
                    return None
                except ConnectionRefusedError:
                    return False
        except Exception as e:
            print(f"Error UDP scan en puerto {port}: {e}")
            return False

    @staticmethod
    def scan_ports(host, ports, scan_type="TCP", timeout=1):
        """Escanea puertos usando el método especificado"""
        open_ports = []
        
        scan_method = {
            "TCP": NetworkScanner.tcp_connect_scan,
            "SYN": NetworkScanner.syn_scan,
            "UDP": NetworkScanner.udp_scan
        }.get(scan_type, NetworkScanner.tcp_connect_scan)

        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_method, host, port, timeout): port 
                      for port in ports}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:  # True o None (para UDP)
                        open_ports.append((port, result))
                except Exception as e:
                    print(f"Error escaneando puerto {port}: {e}")
        
        duration = time.time() - start_time
        return open_ports, duration

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Scanner")
        self.root.geometry("800x650")
        
        self.create_widgets()
        self.setup_style()
        
    def setup_style(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0")
        style.configure("TButton", padding=5)
        style.configure("Red.TButton", foreground="red")
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Notebook (Pestañas)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña de Subred
        subnet_tab = ttk.Frame(notebook)
        notebook.add(subnet_tab, text="Subred Scan")
        
        self.create_subnet_tab(subnet_tab)
        
        # Pestaña de Puertos
        port_tab = ttk.Frame(notebook)
        notebook.add(port_tab, text="Port Scan")
        
        self.create_port_tab(port_tab)
        
        # Área de resultados
        result_frame = ttk.LabelFrame(main_frame, text="Resultados", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.result_text = tk.Text(result_frame, wrap=tk.WORD, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(result_frame, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Barra de estado
        self.status_var = tk.StringVar(value="Listo")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=5)
    
    def create_subnet_tab(self, parent):
        ttk.Label(parent, text="Subred (ej. 192.168.1.0/24):").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.entry_subnet = ttk.Entry(parent, width=25)
        self.entry_subnet.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(parent, text="Timeout (seg):").grid(
            row=1, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.entry_subnet_timeout = ttk.Entry(parent, width=5)
        self.entry_subnet_timeout.insert(0, "1")
        self.entry_subnet_timeout.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        scan_btn = ttk.Button(parent, text="Escanear Subred", 
                            command=self.scan_subnet)
        scan_btn.grid(row=2, column=0, columnspan=2, pady=10)
    
    def create_port_tab(self, parent):
        ttk.Label(parent, text="Host o IP:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.entry_host = ttk.Entry(parent, width=25)
        self.entry_host.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(parent, text="Puertos (ej. 80,443 o 1-100):").grid(
            row=1, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.entry_ports = ttk.Entry(parent, width=25)
        self.entry_ports.insert(0, "1-1024")
        self.entry_ports.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(parent, text="Tipo de Escaneo:").grid(
            row=2, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.scan_type = tk.StringVar(value="TCP")
        scan_options = ["TCP", "SYN", "UDP"] if SCAPY_AVAILABLE else ["TCP", "UDP"]
        self.scan_menu = ttk.OptionMenu(
            parent, self.scan_type, "TCP", *scan_options)
        self.scan_menu.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(parent, text="Timeout (seg):").grid(
            row=3, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.entry_port_timeout = ttk.Entry(parent, width=5)
        self.entry_port_timeout.insert(0, "1")
        self.entry_port_timeout.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        scan_btn = ttk.Button(parent, text="Escanear Puertos", 
                            command=self.scan_ports)
        scan_btn.grid(row=4, column=0, columnspan=2, pady=10)
    
    def process_ports(self, port_str):
        """Convierte el string de puertos a una lista de números"""
        ports = set()
        parts = port_str.split(",")
        for part in parts:
            part = part.strip()
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
            3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
            27017: "MongoDB", 5432: "PostgreSQL", 6379: "Redis"
        }
        return {port: common_services.get(port, "Desconocido") for port in ports}
    
    def scan_subnet(self):
        """Escanea una subred completa"""
        subnet = self.entry_subnet.get()
        
        try:
            timeout = float(self.entry_subnet_timeout.get())
        except ValueError:
            timeout = 1.0
        
        if not subnet:
            messagebox.showwarning("Advertencia", "Debe especificar una subred")
            return
        
        self.result_text.delete(1.0, tk.END)
        self.status_var.set(f"Escaneando subred {subnet}...")
        self.root.update()
        
        try:
            active_hosts = NetworkScanner.scan_network(subnet)
            
            self.result_text.insert(tk.END, f"=== RESULTADOS SUBRED ===\n")
            self.result_text.insert(tk.END, f"Subred: {subnet}\n")
            self.result_text.insert(tk.END, f"Hosts activos encontrados: {len(active_hosts)}\n\n")
            
            for host in active_hosts:
                self.result_text.insert(tk.END, f"• {host}\n")
            
            self.status_var.set(
                f"Escaneo completado - {len(active_hosts)} hosts activos en {subnet}")
        except Exception as e:
            messagebox.showerror("Error", f"Error escaneando subred: {str(e)}")
            self.status_var.set("Error en escaneo de subred")
        finally:
            self.root.update()
    
    def scan_ports(self):
        """Escanea puertos en un host específico"""
        host = self.entry_host.get()
        port_str = self.entry_ports.get()
        scan_type = self.scan_type.get()
        
        try:
            timeout = float(self.entry_port_timeout.get())
        except ValueError:
            timeout = 1.0
        
        if not host:
            messagebox.showwarning("Advertencia", "Debe especificar un host o IP")
            return
        
        self.result_text.delete(1.0, tk.END)
        self.status_var.set(f"Iniciando escaneo {scan_type} en {host}...")
        self.root.update()
        
        try:
            # Resolver el hostname si es necesario
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                ip = host
            
            # Procesar los puertos a escanear
            ports = self.process_ports(port_str)
            
            self.result_text.insert(tk.END, f"=== ESCANEO DE PUERTOS ===\n")
            self.result_text.insert(tk.END, f"Host: {host} ({ip})\n")
            self.result_text.insert(tk.END, f"Tipo: {scan_type}\n")
            self.result_text.insert(tk.END, f"Puertos: {port_str}\n")
            self.result_text.insert(tk.END, f"Timeout: {timeout} segundos\n\n")
            
            # Realizar el escaneo
            open_ports, duration = NetworkScanner.scan_ports(ip, ports, scan_type, timeout)
            
            # Mostrar resultados
            if open_ports:
                services = self.detect_services([port for port, _ in open_ports])
                self.result_text.insert(tk.END, "PUERTOS ABIERTOS:\n")
                
                for port, status in sorted(open_ports, key=lambda x: x[0]):
                    service = services.get(port, "Desconocido")
                    status_text = "Abierto" if status is True else "Filtrado (UDP)" if status is None else "Cerrado"
                    self.result_text.insert(tk.END, 
                        f"• Puerto {port:5} - {service:15} - {status_text}\n")
            else:
                self.result_text.insert(tk.END, "No se encontraron puertos abiertos.\n")
            
            self.result_text.insert(tk.END, f"\nEscaneo completado en {duration:.2f} segundos\n")
            self.status_var.set(
                f"Escaneo {scan_type} completado - {len(open_ports)} puertos abiertos en {host}")
        except ImportError as e:
            messagebox.showerror("Error", 
                f"Escaneo SYN requiere Scapy. Instale con: pip install scapy")
            self.status_var.set("Error: Scapy no instalado")
        except Exception as e:
            messagebox.showerror("Error", f"Error en escaneo de puertos: {str(e)}")
            self.status_var.set("Error en escaneo de puertos")
        finally:
            self.root.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    
    # Mostrar advertencia si Scapy no está disponible
    if not SCAPY_AVAILABLE:
        messagebox.showwarning(
            "Advertencia", 
            "El escaneo SYN no está disponible. Instale Scapy con: pip install scapy")
    
    root.mainloop()