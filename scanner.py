import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed, FIRST_COMPLETED
import time
from datetime import datetime
import threading

# Configuración de puertos comunes con sus servicios asociados
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

# Intenta importar Scapy para escaneo SYN (requiere permisos root)
try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class EscanerRed:
    @staticmethod
    def ping_host(ip, timeout=1, stop_event=None):
        """Realiza ping a un host y obtiene su nombre si está disponible"""
        if stop_event and stop_event.is_set():
            return False, None
            
        sistema = platform.system()
        param = "-n" if sistema == "Windows" else "-c"
        timeout_param = "-w" if sistema == "Windows" else "-W"
        timeout_val = str(timeout * 1000) if sistema == "Windows" else str(timeout)
        
        command = ["ping", param, "1", timeout_param, timeout_val, ip]
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, timeout=timeout+1)
            
            # Si el ping fue exitoso, intentamos obtener el nombre del host
            host_name = None
            if output.returncode == 0:
                try:
                    host_name = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    host_name = "Nombre no disponible"
            
            return output.returncode == 0, host_name
        except:
            return False, None

    @staticmethod
    def tcp_connect_scan(host, port, timeout=1, stop_event=None):
        """Escaneo TCP Connect (estándar)"""
        if stop_event and stop_event.is_set():
            return False
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception as e:
            print(f"Error TCP Connect en puerto {port}: {e}")
            return False

    @staticmethod
    def syn_scan(host, port, timeout=1, stop_event=None):
        """Escaneo SYN (requiere scapy y permisos root)"""
        if stop_event and stop_event.is_set():
            return False
            
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
    def obtener_banner(host, port, timeout=2, stop_event=None):
        """Obtiene el banner de un servicio"""
        if stop_event and stop_event.is_set():
            return None
            
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
    def escanear_puertos(host, ports, scan_type="TCP", timeout=1, get_banners=False, stop_event=None):
        """Escanea puertos con el método especificado"""
        open_ports = []
        scan_method = {
            "TCP": EscanerRed.tcp_connect_scan,
            "SYN": EscanerRed.syn_scan
        }.get(scan_type, EscanerRed.tcp_connect_scan)

        # Reducimos el número de workers para mayor compatibilidad
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_method, host, port, timeout, stop_event): port for port in ports}
            
            for future in as_completed(futures):
                if stop_event and stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return []
                    
                port = futures[future]
                try:
                    if future.result():  # Si el puerto está abierto
                        banner = None
                        if get_banners and not (stop_event and stop_event.is_set()):
                            banner = EscanerRed.obtener_banner(host, port, timeout, stop_event)
                        open_ports.append((port, banner))
                except Exception as e:
                    print(f"Error escaneando puerto {port}: {e}")
        
        return open_ports

    @staticmethod
    def escanear_subred(subnet, ports=None, scan_ports=False, scan_type="TCP", timeout=1, stop_event=None):
        """Escanea una subred y opcionalmente sus puertos, devuelve nombres de host"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            active_hosts = []
            port_results = {}
            host_names = {}  # Diccionario para almacenar nombres de host
            
            # Reducimos el número de workers para mayor compatibilidad
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(EscanerRed.ping_host, str(host), timeout, stop_event): host for host in network.hosts()}
                
                for future in as_completed(futures):
                    if stop_event and stop_event.is_set():
                        executor.shutdown(wait=False, cancel_futures=True)
                        return [], {}, {}
                        
                    host = futures[future]
                    is_active, host_name = future.result()
                    if is_active:
                        host_str = str(host)
                        active_hosts.append(host_str)
                        host_names[host_str] = host_name  # Almacenamos el nombre del host
                        
                        if scan_ports and ports and not (stop_event and stop_event.is_set()):
                            open_ports = EscanerRed.escanear_puertos(
                                host_str, ports, scan_type, timeout, True, stop_event)
                            if open_ports:
                                port_results[host_str] = open_ports
            
            return active_hosts, port_results, host_names
        except ValueError as e:
            raise ValueError(f"Subred no válida: {str(e)}")

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner Avanzado de Red")
        self.root.geometry("900x750")
        
        # Variables para controlar el escaneo en curso
        self.scan_in_progress = False
        self.scan_cancelled = False
        self.scan_window = None  # Referencia a la ventana de escaneo
        self.stop_event = None   # Evento para detener el escaneo
        
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        """Configura los estilos visuales de la interfaz"""
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=('Arial', 10))
        style.configure("TButton", font=('Arial', 10), padding=5)
        style.configure("TNotebook", font=('Arial', 10, 'bold'))
        style.configure("TNotebook.Tab", font=('Arial', 10), padding=[10, 5])
        style.configure("Bold.TButton", font=('Arial', 10, 'bold'))
        
    def create_widgets(self):
        """Crea todos los elementos de la interfaz gráfica"""
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
        self.save_button = ttk.Button(button_frame, text="Guardar Resultado", 
                                    command=self.save_results, style="Bold.TButton")
        self.save_button.pack(side=tk.LEFT, padx=5)
        
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
        """Crea la pestaña de escaneo de subred"""
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
        
        self.scan_button = ttk.Button(tab, text="Iniciar Escaneo", 
                                    command=self.start_subnet_scan)
        self.scan_button.grid(row=5, column=0, columnspan=2, pady=10)
        
        self.port_options_frame.grid_remove()
    
    def create_hosts_tab(self, notebook):
        """Crea la pestaña de escaneo de hosts individuales"""
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
        
        self.scan_host_button = ttk.Button(tab, text="Escanear Host", 
                                        command=self.start_port_scan)
        self.scan_host_button.grid(row=6, column=0, columnspan=2, pady=10)
    
    def show_scan_window(self, target):
        """Muestra la ventana de progreso del escaneo"""
        if self.scan_window is not None:
            return
            
        self.scan_window = tk.Toplevel(self.root)
        self.scan_window.title("Escaneando...")
        self.scan_window.geometry("400x200")
        self.scan_window.resizable(False, False)
        self.scan_window.protocol("WM_DELETE_WINDOW", self.cancel_scan_from_window)
        
        # Centrar la ventana sobre la principal
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        
        scan_width = 400
        scan_height = 200
        pos_x = main_x + (main_width - scan_width) // 2
        pos_y = main_y + (main_height - scan_height) // 2
        
        self.scan_window.geometry(f"+{pos_x}+{pos_y}")
        
        # Contenido de la ventana
        frame = ttk.Frame(self.scan_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=f"Escaneando: {target}", 
                 font=('Arial', 10, 'bold')).pack(pady=(0, 15))
        
        self.progress_label = ttk.Label(frame, text="Preparando escaneo...")
        self.progress_label.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(frame, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        self.progress_bar.start(10)
        
        # Botón de cancelar más visible
        cancel_btn = ttk.Button(frame, text="Cancelar Escaneo", 
                              command=self.cancel_scan_from_window,
                              style="Bold.TButton")
        cancel_btn.pack(pady=10, ipadx=10, ipady=5)
    
    def cancel_scan_from_window(self):
        """Maneja la cancelación desde la ventana de escaneo"""
        if messagebox.askyesno("Confirmar", "¿Desea cancelar el escaneo en curso?"):
            self.cancel_scan()
    
    def close_scan_window(self):
        """Cierra la ventana de progreso del escaneo"""
        if self.scan_window:
            self.progress_bar.stop()
            self.scan_window.destroy()
            self.scan_window = None
    
    def toggle_port_options(self):
        """Muestra/oculta las opciones de puertos según la selección"""
        if self.scan_ports_var.get():
            self.port_options_frame.grid()
        else:
            self.port_options_frame.grid_remove()
    
    def get_ports_to_scan(self, port_type_var, custom_entry):
        """Obtiene la lista de puertos a escanear según la selección del usuario"""
        if port_type_var.get() == "common":
            return list(PUERTOS_COMUNES.keys())
        else:
            return self.parse_ports(custom_entry.get())
    
    def parse_ports(self, port_str):
        """Convierte una cadena de puertos (ej. "80,443,1000-2000") en una lista de números"""
        ports = set()
        parts = port_str.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    if start < 1 or end > 65535 or start > end:
                        raise ValueError("Rango de puertos inválido (1-65535)")
                    ports.update(range(start, end + 1))
                except ValueError:
                    raise ValueError("Formato de rango de puertos inválido. Use: inicio-fin")
            else:
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError("Número de puerto inválido (1-65535)")
                    ports.add(port)
                except ValueError:
                    raise ValueError("Puerto debe ser un número entero")
        return sorted(ports)
    
    def start_subnet_scan(self):
        """Inicia el escaneo de subred"""
        if self.scan_in_progress:
            return
            
        subnet = self.subnet_entry.get()
        scan_ports = self.scan_ports_var.get()
        
        try:
            timeout = float(self.timeout_entry.get())
            if timeout <= 0:
                raise ValueError("El timeout debe ser mayor que 0")
        except ValueError:
            messagebox.showerror("Error", "Timeout inválido. Debe ser un número mayor que 0")
            return
        
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
        
        self.prepare_for_scan()
        self.result_text.delete(1.0, tk.END)
        self.status_var.set(f"Escaneando subred {subnet}...")
        self.root.update()
        
        # Crear evento para detener el escaneo
        self.stop_event = threading.Event()
        
        # Ejecutar el escaneo en un hilo separado para no bloquear la interfaz
        scan_thread = threading.Thread(
            target=self.run_subnet_scan,
            args=(subnet, ports, scan_ports, timeout),
            daemon=True
        )
        scan_thread.start()
    
    def run_subnet_scan(self, subnet, ports, scan_ports, timeout):
        """Ejecuta el escaneo de subred en segundo plano"""
        try:
            start_time = time.time()
            
            # Actualizar progreso
            self.root.after(0, lambda: self.update_scan_progress("Buscando hosts activos..."))
            
            active_hosts, port_results, host_names = EscanerRed.escanear_subred(
                subnet, ports, scan_ports, self.scan_type_var.get(), timeout, self.stop_event)
            duration = time.time() - start_time
            
            if self.scan_cancelled:
                self.on_scan_complete("Escaneo cancelado")
                return
                
            self.display_subnet_results(subnet, active_hosts, port_results, host_names, duration)
            self.on_scan_complete(f"Escaneo completado - {len(active_hosts)} hosts activos")
        except Exception as e:
            self.on_scan_complete("Error en escaneo")
            self.show_error_message(f"Error en escaneo: {str(e)}")
    
    def start_port_scan(self):
        """Inicia el escaneo de puertos en un host individual"""
        if self.scan_in_progress:
            return
            
        host = self.host_entry.get()
        
        try:
            timeout = float(self.timeout_host_entry.get())
            if timeout <= 0:
                raise ValueError("El timeout debe ser mayor que 0")
        except ValueError:
            messagebox.showerror("Error", "Timeout inválido. Debe ser un número mayor que 0")
            return
        
        if not host:
            messagebox.showwarning("Advertencia", "Debe especificar un host")
            return
        
        try:
            ports = self.get_ports_to_scan(self.port_type_host_var, self.custom_ports_host_entry)
        except ValueError as e:
            messagebox.showerror("Error", f"Formato de puertos inválido: {str(e)}")
            return
        
        self.prepare_for_scan()
        self.result_text.delete(1.0, tk.END)
        self.status_var.set(f"Escaneando host {host}...")
        self.root.update()
        
        # Crear evento para detener el escaneo
        self.stop_event = threading.Event()
        
        # Ejecutar el escaneo en un hilo separado para no bloquear la interfaz
        scan_thread = threading.Thread(
            target=self.run_port_scan,
            args=(host, ports, timeout),
            daemon=True
        )
        scan_thread.start()
    
    def run_port_scan(self, host, ports, timeout):
        """Ejecuta el escaneo de puertos en segundo plano"""
        try:
            start_time = time.time()
            
            # Actualizar progreso
            self.root.after(0, lambda: self.update_scan_progress(f"Escaneando puertos en {host}..."))
            
            open_ports = EscanerRed.escanear_puertos(
                host, ports, self.scan_type_host_var.get(), 
                timeout, self.get_banners_var.get(), self.stop_event)
            duration = time.time() - start_time
            
            if self.scan_cancelled:
                self.on_scan_complete("Escaneo cancelado")
                return
                
            # Obtener el nombre del host
            host_name = None
            try:
                host_name = socket.gethostbyaddr(host)[0]
            except (socket.herror, socket.gaierror):
                host_name = "Nombre no disponible"
                
            self.display_port_results(host, host_name, open_ports, duration)
            self.on_scan_complete(f"Escaneo completado - {len(open_ports)} puertos abiertos")
        except Exception as e:
            self.on_scan_complete("Error en escaneo")
            self.show_error_message(f"Error en escaneo: {str(e)}")
    
    def prepare_for_scan(self):
        """Prepara la interfaz para un nuevo escaneo"""
        self.scan_in_progress = True
        self.scan_cancelled = False
        self.scan_button.config(state=tk.DISABLED)
        self.scan_host_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        
        # Mostrar ventana de escaneo
        target = self.subnet_entry.get() if hasattr(self, 'subnet_entry') else self.host_entry.get()
        self.show_scan_window(target)
        
    def on_scan_complete(self, message):
        """Limpia después de completar el escaneo"""
        self.scan_in_progress = False
        self.scan_cancelled = False
        self.scan_button.config(state=tk.NORMAL)
        self.scan_host_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.status_var.set(message)
        
        # Cerrar ventana de escaneo
        self.close_scan_window()
    
    def update_scan_progress(self, message):
        """Actualiza el mensaje de progreso en la ventana de escaneo"""
        if self.scan_window and self.progress_label:
            self.progress_label.config(text=message)
            self.scan_window.update()
    
    def cancel_scan(self):
        """Cancela el escaneo en curso inmediatamente"""
        if self.scan_in_progress:
            self.scan_cancelled = True
            self.status_var.set("Cancelando escaneo...")
            
            # Activar el evento de detención
            if self.stop_event:
                self.stop_event.set()
            
            # Forzar actualización de la interfaz
            self.root.update()
    
    def show_error_message(self, message):
        """Muestra un mensaje de error en el hilo principal"""
        self.root.after(0, lambda: messagebox.showerror("Error", message))
    
    def display_subnet_results(self, subnet, active_hosts, port_results, host_names, duration):
        """Muestra los resultados del escaneo de subred con nombres de host"""
        self.result_text.insert(tk.END, "=== RESULTADOS DE ESCANEO ===\n")
        self.result_text.insert(tk.END, f"Subred: {subnet}\n")
        self.result_text.insert(tk.END, f"Hosts activos encontrados: {len(active_hosts)}\n")
        self.result_text.insert(tk.END, f"Tiempo de escaneo: {duration:.2f} segundos\n\n")
        
        if port_results:
            self.result_text.insert(tk.END, "HOSTS CON PUERTOS ABIERTOS:\n")
            for host, ports_info in port_results.items():
                host_name = host_names.get(host, "Nombre no disponible")
                self.result_text.insert(tk.END, f"\n• {host} ({host_name}):\n")
                for port, banner in ports_info:
                    service = PUERTOS_COMUNES.get(port, "Desconocido")
                    self.result_text.insert(tk.END, f"    - Puerto {port}: {service}")
                    if banner:
                        self.result_text.insert(tk.END, f" | Banner: {banner[:100]}...\n")
                    else:
                        self.result_text.insert(tk.END, "\n")
        
        self.result_text.insert(tk.END, "\nTODOS LOS HOSTS ACTIVOS:\n")
        for host in sorted(active_hosts):
            host_name = host_names.get(host, "Nombre no disponible")
            self.result_text.insert(tk.END, f"• {host} ({host_name})\n")
    
    def display_port_results(self, host, host_name, open_ports, duration):
        """Muestra los resultados del escaneo de puertos con nombre de host"""
        self.result_text.insert(tk.END, "=== RESULTADOS DE ESCANEO ===\n")
        self.result_text.insert(tk.END, f"Host: {host} ({host_name})\n")
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
    
    # Configurar el protocolo para manejar cierre de ventana durante escaneo
    def on_closing():
        if app.scan_in_progress:
            if messagebox.askokcancel("Salir", "Hay un escaneo en progreso. ¿Desea cancelar y salir?"):
                app.cancel_scan()
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
