1:
import socket  # Importa la librería socket, que permite crear conexiones de red

def escanear_puerto(host, puerto):
    try:
        # Crear un socket TCP/IPv4
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Establecer un tiempo máximo de espera de 1 segundo
        s.settimeout(1)

        # Intentar conectarse al host en el puerto especificado
        s.connect((host, puerto))

        # Si la conexión tiene éxito, el puerto está abierto
        print(f"Puerto {puerto} está abierto")

        # Cerrar la conexión
        s.close()

    except:
        # Si ocurre cualquier excepción (por ejemplo, tiempo de espera o conexión rechazada),
        # se considera que el puerto está cerrado o no responde
        print(f"Puerto {puerto} está cerrado o no responde")

# --------------------- EJECUCIÓN DEL ESCÁNER ---------------------

# Dirección IP del host a escanear
host = "192.168.1.1"

# Lista de puertos comunes a escanear: 
# 22 (SSH), 80 (HTTP), 443 (HTTPS)
puertos = [22, 80, 443]

# Bucle para escanear cada puerto de la lista
for puerto in puertos:
    escanear_puerto(host, puerto)

2:
import socket         # Para conexiones de red (escaneo de puertos)
import subprocess     # Para ejecutar comandos del sistema (ping)

def ping_host(ip):
    """
    Realiza un ping a una IP para verificar si está activa.

    Args:
        ip (str): Dirección IP a verificar.

    Returns:
        bool: True si la IP respondió al ping, False si no respondió.
    """
    # Ejecuta el comando 'ping -c 1 [ip]' para enviar 1 paquete ICMP
    response = subprocess.call(['ping', '-c', '1', ip],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    # Devuelve True si el código de salida fue 0 (respuesta exitosa)
    return response == 0

def escanear_puerto(host, puerto):
    """
    Intenta establecer una conexión TCP con el host en un puerto específico.

    Args:
        host (str): Dirección IP o hostname del host.
        puerto (int): Puerto a escanear.
    """
    try:
        # Crear un socket TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Establecer un tiempo máximo de espera de 1 segundo
        s.settimeout(1)

        # Intentar conectarse al puerto
        s.connect((host, puerto))

        # Si se logra conectar, el puerto está abierto
        print(f" Puerto {puerto} está abierto en {host}")
        s.close()

    except:
        # Si no se puede conectar (tiempo de espera o error), el puerto está cerrado
        print(f"❌ Puerto {puerto} está cerrado en {host}")

def escanear_subred(subred):
    """
    Escanea una subred completa (por ejemplo, 192.168.1.x) en busca de hosts activos.
    Luego escanea puertos comunes en cada host activo encontrado.

    Args:
        subred (str): Prefijo de la subred (por ejemplo, '192.168.1')
    """
    print(f"🔍 Iniciando escaneo en la subred {subred}.0/24...\n")

    # Iterar sobre todos los posibles hosts de la subred (de .1 a .254)
    for i in range(1, 255):
        ip = f"{subred}.{i}"

        # Verificar si la IP está activa mediante ping
        if ping_host(ip):
            print(f"\n📡 Host activo encontrado: {ip}")

            # Escanear puertos comunes en ese host
            for puerto in [22, 80, 443]:  # SSH, HTTP, HTTPS
                escanear_puerto(ip, puerto)

# --------------------- EJECUCIÓN PRINCIPAL ---------------------

# Definir la subred a escanear (sin el último octeto)
subred = "192.168.1"

# Llamar a la función para iniciar el escaneo
escanear_subred(subred)

3:

import socket
import subprocess
from scapy.all import sr1, IP, TCP  # Scapy: para escaneo SYN y manipulación de paquetes

def ping_host(ip):
    """
    Realiza un ping a una IP para verificar si está activa (responde).
    
    Args:
        ip (str): Dirección IP a verificar.
    
    Returns:
        bool: True si la IP responde al ping, False si no.
    """
    # Enviar un solo paquete ICMP con 'ping -c 1 [ip]'
    response = subprocess.call(['ping', '-c', '1', ip],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    return response == 0

def syn_scan(host, puerto):
    """
    Realiza un escaneo SYN (half-open scan) al puerto especificado en el host.
    Este tipo de escaneo es más sigiloso que una conexión completa.

    Args:
        host (str): Dirección IP del host objetivo.
        puerto (int): Puerto a escanear.
    """
    # Crear el paquete IP y TCP con flag SYN ("S")
    ip = IP(dst=host)
    syn = TCP(dport=puerto, flags="S")

    # Enviar el paquete y esperar respuesta (timeout de 1 segundo)
    respuesta = sr1(ip/syn, timeout=1, verbose=0)

    # Analizar la respuesta:
    if respuesta is None:
        # No hubo respuesta, posiblemente el puerto está cerrado o filtrado
        print(f"❌ Puerto {puerto} está cerrado o filtrado en {host}")

    elif respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x12:
        # Se recibió un SYN-ACK => Puerto abierto
        print(f"✅ Puerto {puerto} está **abierto** en {host}")

        # Enviar un RST para no completar la conexión (opcional en escaneo SYN)
        rst = TCP(dport=puerto, flags="R")
        sr1(ip/rst, timeout=1, verbose=0)

    else:
        # Cualquier otra respuesta => puerto cerrado o con comportamiento no esperado
        print(f"❌ Puerto {puerto} está cerrado en {host}")

def escanear_subred(subred):
    """
    Escanea todos los hosts de una subred y verifica si están activos.
    Si lo están, realiza escaneo SYN en los puertos definidos.

    Args:
        subred (str): Prefijo de la subred, por ejemplo '192.168.1'
    """
    print(f"🔍 Iniciando escaneo en la subred {subred}.0/24...\n")

    for i in range(1, 255):
        ip = f"{subred}.{i}"

        # Verificar si el host responde a ping
        if ping_host(ip):
            print(f"\n📡 Host activo encontrado: {ip}")

            # Escanear puertos comunes en ese host
            for puerto in [22, 80, 443]:  # Puertos típicos: SSH, HTTP, HTTPS
                syn_scan(ip, puerto)

# --------------------- EJECUCIÓN PRINCIPAL ---------------------

# Definir la subred que se desea escanear
subred = "192.168.1"

# Iniciar el escaneo
escanear_subred(subred)


4:

import socket
import subprocess
from scapy.all import sr1, IP, TCP
from tkinter import *
from tkinter import messagebox

# -------------------- Lógica del escaneo --------------------

class EscanerRed:
    @staticmethod
    def ping_host(ip):
        """
        Realiza un ping a una IP para verificar si está activa.
        
        Args:
            ip (str): Dirección IP a verificar.
        
        Returns:
            bool: True si responde, False si no.
        """
        response = subprocess.call(['ping', '-c', '1', ip],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        return response == 0

    @staticmethod
    def syn_scan(host, puerto):
        """
        Realiza un escaneo SYN al puerto especificado en el host.

        Args:
            host (str): Dirección IP o nombre del host a escanear.
            puerto (int): Puerto a escanear.

        Returns:
            str: Resultado del escaneo como texto.
        """
        ip = IP(dst=host)
        syn = TCP(dport=puerto, flags="S")

        # Enviar el paquete y esperar una respuesta
        respuesta = sr1(ip/syn, timeout=1, verbose=0)

        if respuesta is None:
            return f"❌ Puerto {puerto} está cerrado o no respondió"
        elif respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x12:
            return f"✅ Puerto {puerto} está **abierto**"
        else:
            return f"❌ Puerto {puerto} está cerrado"

# -------------------- Interfaz Gráfica (GUI) --------------------

class AplicacionGUI:
    def __init__(self, master):
        """
        Constructor de la interfaz gráfica.

        Args:
            master (Tk): Ventana principal de la aplicación.
        """
        self.master = master
        self.master.title("Escáner de Red")
        self.master.geometry("400x300")

        # Campo de entrada para la IP o hostname
        self.host_entry = Entry(master, width=30)
        self.host_entry.pack(pady=10)
        self.host_entry.insert(0, "192.168.1.1")  # Valor por defecto

        # Botón para iniciar el escaneo
        self.scan_button = Button(master, text="Escanear Puerto 80", command=self.iniciar_escaneo)
        self.scan_button.pack(pady=10)

    def iniciar_escaneo(self):
        """
        Llama al escaneo SYN y muestra el resultado en una ventana emergente.
        """
        host = self.host_entry.get()
        result = EscanerRed.syn_scan(host, 80)  # Puerto 80 como ejemplo
        messagebox.showinfo("Resultado del escaneo", result)

# -------------------- Ejecución del programa --------------------

root = Tk()                  # Crear la ventana principal
app = AplicacionGUI(root)   # Crear la app pasando la ventana
root.mainloop()             # Ejecutar el loop principal de la GUI
