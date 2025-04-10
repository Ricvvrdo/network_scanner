## Descripción General
Este script implementa una herramienta avanzada de escaneo de red con interfaz gráfica usando Tkinter. Permite detectar hosts activos en una subred mediante ping, y escanear puertos utilizando TCP Connect o SYN scan (si se dispone de scapy y permisos). También puede obtener banners de servicios abiertos.

## Estructura Principal

1. EscanerRed 
Contiene todos los métodos relacionados con el escaneo de red y puertos.

Métodos:
ping_host(ip, timeout): Verifica si un host responde al ping.

tcp_connect_scan(host, port, timeout): Escaneo tradicional TCP connect.

syn_scan(host, port, timeout): Escaneo SYN (requiere scapy y privilegios).

obtener_banner(host, port, timeout): Extrae el banner del servicio si es posible.

escanear_puertos(host, ports, scan_type, timeout, get_banners): Escanea múltiples puertos en un host.

escanear_subred(subnet, ports, scan_ports, scan_type, timeout): Escanea una subred y opcionalmente realiza escaneo de puertos en hosts activos.

2. NetworkScannerApp (clase de GUI)
Crea la interfaz gráfica con pestañas para escaneo de subred y de hosts individuales.

Funciones principales:
Pestaña de Subred:

Entrada de subred (CIDR)

Opción para escanear puertos en hosts activos

Selección de puertos comunes o personalizados

Tipo de escaneo: TCP o SYN

Timeout

Botón para iniciar escaneo

Pestaña de Host:

Entrada de IP o hostname

Selección de puertos comunes o personalizados (puede incluir rangos)

Opción para obtener banners

Tipo de escaneo y timeout

Botón para escanear host

Botón Global para guardar los resultados del escaneo a un archivo.

## Estructura inicial del proyecto

  /network_scanner
    ├── scanner.py        Código principal
    ├── requirements.txt  Dependencias
    ├── README.md         Documentación
    └── /tests            Pruebas unitarias

Integrantes:
Alexis callejas
Ricardo Duarte
Benjamin Rojas
