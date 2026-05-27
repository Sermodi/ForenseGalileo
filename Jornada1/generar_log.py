"""
Genera un sistema.log extendido (~100 lineas) para el ejercicio 5.2
Uso: python generar_log.py evidencias_usb/logs/sistema.log
"""

import random
import sys
from datetime import datetime, timedelta

BASE = datetime(2024, 3, 15, 6, 0, 0)

USUARIOS = ["admin", "jlopez", "mgarcia", "root", "svc_backup"]
IPS_OK   = ["192.168.1.101", "192.168.1.102", "10.0.0.5", "10.0.0.12"]
IPS_MAL  = ["185.220.101.45", "194.165.16.11", "45.142.212.100"]
ARCHIVOS = [
    "/docs/contrato.docx", "/docs/nominas_2024.xlsx",
    "/home/admin/.ssh/id_rsa", "/etc/shadow", "/etc/passwd",
    "/var/backup/dump.tar.gz", "/tmp/c.docx",
]
USB_DEVICES = [
    "Vendor=0930 Product=6545",
    "Vendor=058f Product=6387",
    "Vendor=1307 Product=0165",
]

PLANTILLAS = [
    # (nivel, modulo, mensaje_template)
    ("INFO",  "auth",   "Usuario {u} ha iniciado sesión desde {ip_ok}"),
    ("INFO",  "auth",   "Usuario {u} ha cerrado sesión"),
    ("INFO",  "file",   "Archivo {f} abierto por {u}"),
    ("INFO",  "file",   "Archivo {f} copiado a /tmp/c.docx"),
    ("INFO",  "file",   "Archivo /tmp/c.docx copiado a /media/usb/c.docx"),
    ("INFO",  "system", "Servicio sshd reiniciado"),
    ("INFO",  "system", "Backup completado: /var/backup/dump.tar.gz"),
    ("INFO",  "net",    "Conexión entrante desde {ip_ok}:22"),
    ("WARN",  "net",    "Conexión saliente a {ip_mal}:443"),
    ("WARN",  "net",    "Múltiples intentos fallidos desde {ip_mal}"),
    ("WARN",  "usb",    "Dispositivo USB conectado: {usb}"),
    ("WARN",  "auth",   "Intento de sudo fallido por {u}"),
    ("WARN",  "file",   "Acceso a archivo sensible {f} por {u}"),
    ("ERROR", "system", "Fallo de acceso a /etc/shadow por usuario {u}"),
    ("ERROR", "auth",   "Contraseña incorrecta para {u} (3 intentos)"),
    ("ERROR", "net",    "Conexión rechazada a {ip_mal}:8080"),
    ("ERROR", "file",   "Permiso denegado al leer {f}"),
    ("ERROR", "system", "Proceso desconocido intentó escribir en /etc/crontab"),
]

def render(template, u, ip_ok, ip_mal, f, usb):
    return (template
        .replace("{u}",      u)
        .replace("{ip_ok}",  ip_ok)
        .replace("{ip_mal}", ip_mal)
        .replace("{f}",      f)
        .replace("{usb}",    usb))

t = BASE
lineas = []

for _ in range(100):
    t += timedelta(seconds=random.randint(10, 300))
    nivel, modulo, tmpl = random.choice(PLANTILLAS)
    msg = render(
        tmpl,
        u      = random.choice(USUARIOS),
        ip_ok  = random.choice(IPS_OK),
        ip_mal = random.choice(IPS_MAL),
        f      = random.choice(ARCHIVOS),
        usb    = random.choice(USB_DEVICES),
    )
    linea = f"{t.strftime('%Y-%m-%d %H:%M:%S')} {nivel:<5} [{modulo}] {msg}"
    lineas.append(linea)

# Insertar los 8 eventos originales en posiciones fijas para que el ejercicio funcione igual
originales = [
    "2024-03-15 08:12:33 INFO  [auth]   Usuario admin ha iniciado sesion desde 192.168.1.101",
    "2024-03-15 08:15:44 INFO  [file]   Archivo /docs/contrato.docx abierto por admin",
    "2024-03-15 08:17:01 WARN  [net]    Conexion saliente a 185.220.101.45:443",
    "2024-03-15 08:17:05 ERROR [system] Fallo de acceso a /etc/shadow por usuario admin",
    "2024-03-15 08:22:18 INFO  [file]   Archivo /docs/contrato.docx copiado a /tmp/c.docx",
    "2024-03-15 08:25:50 WARN  [usb]    Dispositivo USB conectado: Vendor=0930 Product=6545",
    "2024-03-15 08:26:03 INFO  [file]   Archivo /tmp/c.docx copiado a /media/usb/c.docx",
    "2024-03-15 08:28:11 INFO  [auth]   Usuario admin ha cerrado sesion",
]
for i, orig in enumerate(originales):
    lineas.insert(10 + i * 10, orig)

# Escribir a fichero (UTF-8 sin BOM) o por pantalla
destino = sys.argv[1] if len(sys.argv) > 1 else None
if destino:
    with open(destino, "w", encoding="utf-8") as f:
        for l in lineas:
            f.write(l + "\n")
    print(f"[+] Log generado en: {destino} ({len(lineas)} lineas)")
else:
    for l in lineas:
        print(l)
