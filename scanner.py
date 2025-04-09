import tkinter as tk
from tkinter import messagebox
import argparse
import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor

# Función para hacer ping a un host
def ping_host(ip, timeout=1):
    sistema = platform.system()
    if sistema == "Windows":
        comando = ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip)]
    else:
        comando = ["ping", "-c", "1", "-W", str(timeout), str(ip)]

    resultado = subprocess.run(comando, stdout=subprocess.DEVNULL)
    return resultado.returncode == 0

# Función para hacer ping sweep
def ping_sweep(subred, timeout=1):
    activos = []
    red = ipaddress.ip_network(subred, strict=False)
    print(f"Escaneando subred: {subred}")
    with ThreadPoolExecutor(max_workers=200) as executor:  # Aumentar trabajadores (hilos)
        resultados = executor.map(lambda ip: (ip, ping_host(ip, timeout)), red.hosts())
        for ip, activo in resultados:
            if activo:
                activos.append(str(ip))
    return activos

# Escaneo de puertos
def scan_ports(host, puertos, timeout=0.2):  # Reducir el timeout a 0.2 segundos
    abiertos = []
    print(f"Escaneando puertos en {host}...")
    with ThreadPoolExecutor(max_workers=200) as executor:  # Aumentar hilos
        futuros = {executor.submit(scan_port, host, puerto, timeout): puerto for puerto in puertos}
        for futuro in futuros:
            puerto = futuros[futuro]
            if futuro.result():
                abiertos.append(puerto)
    return abiertos

def scan_port(host, puerto, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    resultado = sock.connect_ex((host, puerto))
    sock.close()
    return resultado == 0

# Detección básica de servicios por puerto común
def detectar_servicios(puertos):
    servicios_comunes = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP"
    }
    return {puerto: servicios_comunes.get(puerto, "Desconocido") for puerto in puertos}

# Procesar argumento de puertos (permite 22,80 o 1-100, etc.)
def procesar_puertos(puerto_str):
    puertos = set()
    partes = puerto_str.split(",")
    for parte in partes:
        if "-" in parte:
            inicio, fin = map(int, parte.split("-"))
            puertos.update(range(inicio, fin + 1))
        else:
            puertos.add(int(parte))
    return sorted(puertos)

# Función principal
def escanear_red():
    subred = entry_subred.get()
    host = entry_host.get()
    puertos = entry_puertos.get()
    escanear_todos = var_escanear_todos.get()

    resultado_text.delete(1.0, tk.END)  # Limpiar resultados previos

    if subred:
        try:
            hosts_activos = ping_sweep(subred)
            resultado_text.insert(tk.END, "Hosts activos:\n")
            for host in hosts_activos:
                resultado_text.insert(tk.END, f" - {host}\n")
        except ValueError:
            messagebox.showerror("Error", "La subred no es válida.")
            return

    if host:
        if escanear_todos:
            lista_puertos = list(range(1, 1025))
        elif puertos:
            lista_puertos = procesar_puertos(puertos)
        else:
            messagebox.showwarning("Advertencia", "Debes especificar --puertos o --escanear-todos con --host.")
            return

        puertos_abiertos = scan_ports(host, lista_puertos)
        if puertos_abiertos:
            resultado_text.insert(tk.END, f"\nPuertos abiertos en {host}:\n")
            for puerto in puertos_abiertos:
                servicio = detectar_servicios([puerto])[puerto]
                resultado_text.insert(tk.END, f" - Puerto {puerto}: {servicio}\n")
        else:
            resultado_text.insert(tk.END, f"No se encontraron puertos abiertos en {host}.\n")

# Configuración de la ventana gráfica
root = tk.Tk()
root.title("Escaneo de Red")
root.geometry("500x400")

# Subred y Host
label_subred = tk.Label(root, text="Subred (ej. 192.168.1.0/24):")
label_subred.pack(pady=5)
entry_subred = tk.Entry(root, width=50)
entry_subred.pack(pady=5)

label_host = tk.Label(root, text="Host para escanear (ej. 192.168.1.1):")
label_host.pack(pady=5)
entry_host = tk.Entry(root, width=50)
entry_host.pack(pady=5)

# Puertos
label_puertos = tk.Label(root, text="Puertos a escanear (ej. 22,80,443 o 1-100):")
label_puertos.pack(pady=5)
entry_puertos = tk.Entry(root, width=50)
entry_puertos.pack(pady=5)

# Opción de escanear todos los puertos comunes
var_escanear_todos = tk.BooleanVar()
check_escanear_todos = tk.Checkbutton(root, text="Escanear puertos comunes (1-1024)", variable=var_escanear_todos)
check_escanear_todos.pack(pady=5)

# Botón de escaneo
boton_escanear = tk.Button(root, text="Escanear", command=escanear_red)
boton_escanear.pack(pady=10)

# Caja de texto para mostrar los resultados
resultado_text = tk.Text(root, width=60, height=10)
resultado_text.pack(pady=10)

root.mainloop()
