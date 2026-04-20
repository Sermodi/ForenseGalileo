import json
#import sys
#import csv
import hashlib
#from datetime import datetime, timezone
from pathlib import Path
#from collections import Counter

ACTIVIDAD_DEMO = [
    {"timestamp": "2026-03-15T08:23:11Z", "usuario": "jperez", "accion": "LOGIN", "ip": "192.168.1.45", "app": "Correo"},
    {"timestamp": "2026-03-15T08:25:00Z", "usuario": "jperez", "accion": "DESCARGA", "ip": "192.168.1.45", "app": "Correo", "archivo": "nominas_2026.xlsx"},
    {"timestamp": "2026-03-15T08:26:30Z", "usuario": "jperez", "accion": "DESCARGA", "ip": "192.168.1.45", "app": "Correo", "archivo": "clientes_db_export.csv"},
    {"timestamp": "2026-03-15T08:27:45Z", "usuario": "jperez", "accion": "SUBIDA", "ip": "192.168.1.45", "app": "Drive", "archivo": "clientes_db_export.csv", "destino": "externo"},
    {"timestamp": "2026-03-15T02:14:00Z", "usuario": "admin", "accion": "LOGIN", "ip": "185.220.101.45", "app": "Panel"},
    {"timestamp": "2026-03-15T02:15:22Z", "usuario": "admin", "accion": "MODIFICACION", "ip": "185.220.101.45", "app": "Panel", "objeto": "permisos_usuarios"},
    {"timestamp": "2026-03-15T02:16:00Z", "usuario": "admin", "accion": "LOGOUT", "ip": "185.220.101.45", "app": "Panel"},
    {"timestamp": "2026-03-15T09:00:00Z", "usuario": "mgarcia", "accion": "LOGIN", "ip": "192.168.1.67", "app": "Correo"},
    {"timestamp": "2026-03-15T09:05:00Z", "usuario": "mgarcia", "accion": "LOGOUT", "ip": "192.168.1.67", "app": "Correo"},
    {"timestamp": "2026-03-16T08:30:00Z", "usuario": "jperez", "accion": "LOGIN", "ip": "10.0.0.22", "app": "VPN"},
    {"timestamp": "2026-03-16T08:32:00Z", "usuario": "jperez", "accion": "DESCARGA", "ip": "10.0.0.22", "app": "FileServer", "archivo": "proyectos_secretos.zip"},
]

GEO_DEMO = [
    {"timestamp": "2026-03-14T20:00:00Z", "lat": 40.4168, "lon": -3.7038, "precision_m": 15, "dispositivo": "iPhone14-jperez"},
    {"timestamp": "2026-03-15T08:10:00Z", "lat": 40.4534, "lon": -3.6890, "precision_m": 10, "dispositivo": "iPhone14-jperez"},
    {"timestamp": "2026-03-15T08:23:00Z", "lat": 40.4534, "lon": -3.6890, "precision_m": 8, "dispositivo": "iPhone14-jperez"},
    {"timestamp": "2026-03-15T09:45:00Z", "lat": 40.4534, "lon": -3.6890, "precision_m": 12, "dispositivo": "iPhone14-jperez"},
    {"timestamp": "2026-03-15T13:00:00Z", "lat": 40.4168, "lon": -3.7038, "precision_m": 20, "dispositivo": "iPhone14-jperez"},
    {"timestamp": "2026-03-16T08:05:00Z", "lat": 40.4534, "lon": -3.6890, "precision_m": 9, "dispositivo": "iPhone14-jperez"},
]


"""Crea ficheros JSON de prueba para los ejercicios."""
directorio = Path("evidencias_json")
directorio.mkdir(exist_ok=True)

ruta_act = directorio / "registro_actividad.json"
ruta_geo = directorio / "historial_ubicaciones.json"

with open(ruta_act, "w", encoding="utf-8") as f:
    json.dump(ACTIVIDAD_DEMO, f, ensure_ascii=False, indent=2)

with open(ruta_geo, "w", encoding="utf-8") as f:
    json.dump(GEO_DEMO, f, ensure_ascii=False, indent=2)

# Hash de integridad
for ruta in [ruta_act, ruta_geo]:
    sha256 = hashlib.sha256(ruta.read_bytes()).hexdigest()
    print(f"[OK] Creado: {ruta}  SHA-256: {sha256[:16]}...")

print("\nFicheros de prueba creados en ./evidencias_json/")
print("Siguiente paso:")
print("  python json_forense.py evidencias_json/registro_actividad.json --tipo actividad")

