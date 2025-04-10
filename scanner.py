import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime

# Configuración de puertos comunes
PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB"
}

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class EscanerRed:
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
    def obtener_banner(host, port, timeout=2):
        """Obtiene el banner de un servicio"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                
                if port == 80 or port == 443:  # HTTP/HTTPS
                    s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
                elif port == 21:  # FTP
                    s.recv(1024)  # Leer banner inicial
                
                banner = s.recv(1024).decode(errors='ignore').strip()
                return banner.split('\n')[0]  # Primera línea del banner
        except Exception as e:
            print(f"Error obteniendo banner en {host}:{port} - {e}")
            return None

    @staticmethod
    def escanear_puertos(host, ports, scan_type="TCP", timeout=1, get_banners=False):
        """Escanea puertos con el método especificado"""
        open_ports = []
        scan_method = {
            "TCP": EscanerRed.tcp_connect_scan,
            "SYN": EscanerRed.syn_scan
        }.get(scan_type, EscanerRed.tcp_connect_scan)

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_method, host, port, timeout): port for port in ports}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():  # Si el puerto está abierto
                        banner = None
                        if get_banners:
                            banner = EscanerRed.obtener_banner(host, port, timeout)
                        open_ports.append((port, banner))
                except Exception as e:
                    print(f"Error escaneando puerto {port}: {e}")
        
        return open_ports

    @staticmethod
    def escanear_subred(subnet, ports=None, scan_ports=False, scan_type="TCP", timeout=1):
        """Escanea una subred y opcionalmente sus puertos"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            active_hosts = []
            port_results = {}
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(EscanerRed.ping_host, str(host), timeout): host for host in network.hosts()}
                
                for future in as_completed(futures):
                    host = futures[future]
                    if future.result():
                        host_str = str(host)
                        active_hosts.append(host_str)
                        
                        if scan_ports and ports:
                            open_ports = EscanerRed.escanear_puertos(host_str, ports, scan_type, timeout, True)
                            if open_ports:
                                port_results[host_str] = open_ports
            
            return active_hosts, port_results
        except ValueError as e:
            raise ValueError(f"Subred no válida: {str(e)}")

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Scanner")
        self.root.geometry("900x750")
        
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=('Arial', 10))
        style.configure("TButton", font=('Arial', 10), padding=5)
        style.configure("TNotebook", font=('Arial', 10, 'bold'))
        style.configure("TNotebook.Tab", font=('Arial', 10), padding=[10, 5])
        style.configure("Bold.TButton", font=('Arial', 10, 'bold'))
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Notebook (Pestañas)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Pestaña de Escaneo de Subred
        self.create_subnet_tab(notebook)
        
        # Pestaña de Escaneo de Hosts
        self.create_hosts_tab(notebook)
        
        # Frame para botones inferiores
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        # Botón para guardar resultados
        save_button = ttk.Button(button_frame, text="Guardar Resultado", 
                               command=self.save_results, style="Bold.TButton")
        save_button.pack(side=tk.LEFT, padx=5)
        
        # Área de resultados
        result_frame = ttk.LabelFrame(main_frame, text="Resultados", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        self.result_text = tk.Text(result_frame, wrap=tk.WORD, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(result_frame, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Barra de estado
        self.status_var = tk.StringVar(value="Listo")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                             relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=(5, 0))
    
    def create_subnet_tab(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Escaneo de Subred")
        
        ttk.Label(tab, text="Subred (ej. 192.168.1.0/24):").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.subnet_entry = ttk.Entry(tab, width=25)
        self.subnet_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        self.scan_ports_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(tab, text="Escanear puertos en hosts activos",
                       variable=self.scan_ports_var, command=self.toggle_port_options).grid(
                           row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        self.port_options_frame = ttk.Frame(tab)
        self.port_options_frame.grid(row=2, column=0, columnspan=2, sticky=tk.W)
        
        self.port_type_var = tk.StringVar(value="common")
        ttk.Radiobutton(self.port_options_frame, text="Puertos comunes",
                       variable=self.port_type_var, value="common").grid(
                           row=0, column=0, padx=5, pady=2, sticky=tk.W)
        ttk.Radiobutton(self.port_options_frame, text="Puertos personalizados:",
                       variable=self.port_type_var, value="custom").grid(
                           row=1, column=0, padx=5, pady=2, sticky=tk.W)
        
        self.custom_ports_entry = ttk.Entry(self.port_options_frame, width=30)
        self.custom_ports_entry.insert(0, "21,22,80,443,3389")
        self.custom_ports_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(tab, text="Tipo de escaneo:").grid(
            row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.scan_type_var = tk.StringVar(value="TCP")
        scan_options = ["TCP", "SYN"] if SCAPY_AVAILABLE else ["TCP"]
        scan_menu = ttk.OptionMenu(tab, self.scan_type_var, "TCP", *scan_options)
        scan_menu.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(tab, text="Timeout (segundos):").grid(
            row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.timeout_entry = ttk.Entry(tab, width=5)
        self.timeout_entry.insert(0, "1")
        self.timeout_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(tab, text="Iniciar Escaneo", 
                  command=self.start_subnet_scan).grid(
                      row=5, column=0, columnspan=2, pady=10)
        
        self.port_options_frame.grid_remove()
    
    def create_hosts_tab(self, notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Escaneo de Hosts")
        
        ttk.Label(tab, text="Host o IP:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.host_entry = ttk.Entry(tab, width=25)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        self.port_type_host_var = tk.StringVar(value="common")
        ttk.Radiobutton(tab, text="Puertos comunes",
                       variable=self.port_type_host_var, value="common").grid(
                           row=1, column=0, padx=5, pady=2, sticky=tk.W)
        ttk.Radiobutton(tab, text="Puertos personalizados:",
                       variable=self.port_type_host_var, value="custom").grid(
                           row=2, column=0, padx=5, pady=2, sticky=tk.W)
        
        self.custom_ports_host_entry = ttk.Entry(tab, width=25)
        self.custom_ports_host_entry.insert(0, "1-1024")
        self.custom_ports_host_entry.grid(row=2, column=1, padx=5, pady=2)
        
        ttk.Label(tab, text="Tipo de escaneo:").grid(
            row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.scan_type_host_var = tk.StringVar(value="TCP")
        scan_options = ["TCP", "SYN"] if SCAPY_AVAILABLE else ["TCP"]
        scan_menu = ttk.OptionMenu(tab, self.scan_type_host_var, "TCP", *scan_options)
        scan_menu.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        self.get_banners_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tab, text="Obtener banners de servicios",
                       variable=self.get_banners_var).grid(
                           row=4, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)
        
        ttk.Label(tab, text="Timeout (segundos):").grid(
            row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.timeout_host_entry = ttk.Entry(tab, width=5)
        self.timeout_host_entry.insert(0, "1")
        self.timeout_host_entry.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(tab, text="Escanear Host", 
                  command=self.start_port_scan).grid(
                      row=6, column=0, columnspan=2, pady=10)
    
    def toggle_port_options(self):
        if self.scan_ports_var.get():
            self.port_options_frame.grid()
        else:
            self.port_options_frame.grid_remove()
    
    def get_ports_to_scan(self, port_type_var, custom_entry):
        if port_type_var.get() == "common":
            return list(PUERTOS_COMUNES.keys())
        else:
            return self.parse_ports(custom_entry.get())
    
    def parse_ports(self, port_str):
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
    
    def start_subnet_scan(self):
        subnet = self.subnet_entry.get()
        scan_ports = self.scan_ports_var.get()
        
        try:
            timeout = float(self.timeout_entry.get())
        except ValueError:
            timeout = 1.0
        
        if not subnet:
            messagebox.showwarning("Advertencia", "Debe especificar una subred")
            return
        
        ports = []
        if scan_ports:
            try:
                ports = self.get_ports_to_scan(self.port_type_var, self.custom_ports_entry)
            except ValueError as e:
                messagebox.showerror("Error", f"Formato de puertos inválido: {str(e)}")
                return
        
        self.result_text.delete(1.0, tk.END)
        self.status_var.set(f"Escaneando subred {subnet}...")
        self.root.update()
        
        try:
            start_time = time.time()
            active_hosts, port_results = EscanerRed.escanear_subred(
                subnet, ports, scan_ports, self.scan_type_var.get(), timeout)
            duration = time.time() - start_time
            
            self.display_subnet_results(subnet, active_hosts, port_results, duration)
            
            self.status_var.set(f"Escaneo completado - {len(active_hosts)} hosts activos")
        except Exception as e:
            messagebox.showerror("Error", f"Error en escaneo: {str(e)}")
            self.status_var.set("Error en escaneo")
        finally:
            self.root.update()
    
    def display_subnet_results(self, subnet, active_hosts, port_results, duration):
        self.result_text.insert(tk.END, "=== RESULTADOS DE ESCANEO ===\n")
        self.result_text.insert(tk.END, f"Subred: {subnet}\n")
        self.result_text.insert(tk.END, f"Hosts activos encontrados: {len(active_hosts)}\n")
        self.result_text.insert(tk.END, f"Tiempo de escaneo: {duration:.2f} segundos\n\n")
        
        if port_results:
            self.result_text.insert(tk.END, "HOSTS CON PUERTOS ABIERTOS:\n")
            for host, ports_info in port_results.items():
                self.result_text.insert(tk.END, f"\n• {host}:\n")
                for port, banner in ports_info:
                    service = PUERTOS_COMUNES.get(port, "Desconocido")
                    self.result_text.insert(tk.END, f"    - Puerto {port}: {service}")
                    if banner:
                        self.result_text.insert(tk.END, f" | Banner: {banner[:100]}...\n")
                    else:
                        self.result_text.insert(tk.END, "\n")
        
        self.result_text.insert(tk.END, "\nTODOS LOS HOSTS ACTIVOS:\n")
        for host in sorted(active_hosts):
            self.result_text.insert(tk.END, f"• {host}\n")
    
    def start_port_scan(self):
        host = self.host_entry.get()
        
        try:
            timeout = float(self.timeout_host_entry.get())
        except ValueError:
            timeout = 1.0
        
        if not host:
            messagebox.showwarning("Advertencia", "Debe especificar un host")
            return
        
        try:
            ports = self.get_ports_to_scan(self.port_type_host_var, self.custom_ports_host_entry)
        except ValueError as e:
            messagebox.showerror("Error", f"Formato de puertos inválido: {str(e)}")
            return
        
        self.result_text.delete(1.0, tk.END)
        self.status_var.set(f"Escaneando host {host}...")
        self.root.update()
        
        try:
            start_time = time.time()
            open_ports = EscanerRed.escanear_puertos(
                host, ports, self.scan_type_host_var.get(), 
                timeout, self.get_banners_var.get())
            duration = time.time() - start_time
            
            self.display_port_results(host, open_ports, duration)
            
            self.status_var.set(f"Escaneo completado - {len(open_ports)} puertos abiertos")
        except Exception as e:
            messagebox.showerror("Error", f"Error en escaneo: {str(e)}")
            self.status_var.set("Error en escaneo")
        finally:
            self.root.update()
    
    def display_port_results(self, host, open_ports, duration):
        self.result_text.insert(tk.END, "=== RESULTADOS DE ESCANEO ===\n")
        self.result_text.insert(tk.END, f"Host: {host}\n")
        self.result_text.insert(tk.END, f"Tipo de escaneo: {self.scan_type_host_var.get()}\n")
        self.result_text.insert(tk.END, f"Tiempo de escaneo: {duration:.2f} segundos\n\n")
        
        if open_ports:
            self.result_text.insert(tk.END, "PUERTOS ABIERTOS:\n")
            for port, banner in sorted(open_ports, key=lambda x: x[0]):
                service = PUERTOS_COMUNES.get(port, "Desconocido")
                self.result_text.insert(tk.END, f"• Puerto {port}: {service}")
                if banner:
                    self.result_text.insert(tk.END, f" | Banner: {banner[:100]}...\n")
                else:
                    self.result_text.insert(tk.END, "\n")
        else:
            self.result_text.insert(tk.END, "No se encontraron puertos abiertos.\n")
    
    def save_results(self):
        """Guarda los resultados del escaneo en un archivo"""
        content = self.result_text.get("1.0", tk.END)
        if not content.strip():
            messagebox.showwarning("Advertencia", "No hay resultados para guardar")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"scan_results_{timestamp}.txt"
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")],
            initialfile=default_filename
        )
        
        if not filepath:
            return
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Éxito", f"Resultados guardados en:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    
    if not SCAPY_AVAILABLE:
        messagebox.showwarning(
            "Advertencia", 
            "El escaneo SYN no está disponible. Instale Scapy con: pip install scapy")
    
    root.mainloop()
