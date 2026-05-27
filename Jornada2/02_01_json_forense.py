#!/usr/bin/env python3
"""
json_forense.py
===============
EJERCICIO 1 — Jornada 2: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Analiza artefactos JSON forenses: registros de actividad de aplicaciones,
datos de geolocalización y logs estructurados. Detecta patrones sospechosos
y genera un informe de hallazgos.

Uso
---
    python json_forense.py <fichero.json> [--tipo actividad|geo|log]
    python json_forense.py --generar-demo   # Genera ficheros de prueba

Ejemplos
--------
    python json_forense.py registro_actividad.json --tipo actividad
    python json_forense.py historial_ubicaciones.json --tipo geo
    python json_forense.py --generar-demo

Dependencias
------------
    Sólo librerías estándar de Python (json, datetime, pathlib, csv)

Autor   : SergioM.
Versión : 1.0
Fecha   : 2026-04-10
"""

import json
import sys
import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter


# ---------------------------------------------------------------------------
# GENERADOR DE DATOS DE PRUEBA
# ---------------------------------------------------------------------------

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


def generar_demos():
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


# ---------------------------------------------------------------------------
# ANÁLISIS DE REGISTRO DE ACTIVIDAD
# ---------------------------------------------------------------------------

IPS_SOSPECHOSAS = {"185.220.101.45", "185.220.101.46", "51.15.0.0"}
ACCIONES_CRITICAS = {"DESCARGA", "SUBIDA", "MODIFICACION", "BORRADO"}
HORA_SOSPECHOSA_INICIO = 0   # medianoche
HORA_SOSPECHOSA_FIN = 6      # 6 AM

def analizar_actividad(registros: list) -> None:
    """Analiza un registro de acciones de usuarios y detecta anomalías."""
    print("\n" + "="*60)
    print("  ANÁLISIS DE REGISTRO DE ACTIVIDAD")
    print("="*60)

    hallazgos = []
    usuarios = Counter()
    acciones = Counter()

    for entrada in registros:
        ts_str = entrada.get("timestamp", "")
        usuario = entrada.get("usuario", "desconocido")
        accion = entrada.get("accion", "")
        ip = entrada.get("ip", "")

        usuarios[usuario] += 1
        acciones[accion] += 1

        # Parsear timestamp — crítico en forense
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            hora = ts.hour
        except ValueError:
            ts = None
            hora = -1

        # Regla 1: IP sospechosa
        if ip in IPS_SOSPECHOSAS:
            hallazgos.append({
                "severidad": "ALTA",
                "regla": "IP_SOSPECHOSA",
                "detalle": f"Acceso desde IP conocida de Tor/VPN: {ip}",
                "evento": entrada
            })

        # Regla 2: Acción crítica en horario nocturno
        if accion in ACCIONES_CRITICAS and HORA_SOSPECHOSA_INICIO <= hora < HORA_SOSPECHOSA_FIN:
            hallazgos.append({
                "severidad": "MEDIA",
                "regla": "ACCION_NOCTURNA",
                "detalle": f"Acción {accion} a las {hora:02d}:{ts.minute:02d}h (fuera de horario)",
                "evento": entrada
            })

        # Regla 3: Subida a destino externo
        if accion == "SUBIDA" and entrada.get("destino") == "externo":
            hallazgos.append({
                "severidad": "ALTA",
                "regla": "EXFILTRACION_POTENCIAL",
                "detalle": f"Archivo subido a destino externo: {entrada.get('archivo', 'N/A')}",
                "evento": entrada
            })

    # Resumen estadístico
    print(f"\n  Total de eventos analizados : {len(registros)}")
    print(f"  Usuarios únicos             : {len(usuarios)}")
    print(f"\n  Acciones más frecuentes:")
    for accion, count in acciones.most_common(5):
        print(f"    {accion:<20} {count:>3} veces")

    # Hallazgos
    print(f"\n  ⚠️  Hallazgos detectados: {len(hallazgos)}")
    for h in hallazgos:
        icono = "🔴" if h["severidad"] == "ALTA" else "🟡"
        print(f"\n  {icono} [{h['severidad']}] {h['regla']}")
        print(f"     {h['detalle']}")
        print(f"     Usuario: {h['evento'].get('usuario')} | TS: {h['evento'].get('timestamp')}")

    # Exportar hallazgos a CSV
    if hallazgos:
        ruta_csv = "hallazgos_actividad.csv"
        campos = ["severidad", "regla", "detalle", "usuario", "timestamp", "ip"]
        with open(ruta_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=campos)
            writer.writeheader()
            for h in hallazgos:
                writer.writerow({
                    "severidad": h["severidad"],
                    "regla": h["regla"],
                    "detalle": h["detalle"],
                    "usuario": h["evento"].get("usuario", ""),
                    "timestamp": h["evento"].get("timestamp", ""),
                    "ip": h["evento"].get("ip", ""),
                })
        print(f"\n  [+] Hallazgos exportados → {ruta_csv}")


# ---------------------------------------------------------------------------
# ANÁLISIS DE GEOLOCALIZACIÓN
# ---------------------------------------------------------------------------

def analizar_geo(registros: list) -> None:
    """Analiza historial de ubicaciones y detecta patrones de movimiento."""
    print("\n" + "="*60)
    print("  ANÁLISIS DE HISTORIAL DE GEOLOCALIZACIÓN")
    print("="*60)

    dispositivos = {}
    for r in registros:
        disp = r.get("dispositivo", "desconocido")
        if disp not in dispositivos:
            dispositivos[disp] = []
        dispositivos[disp].append(r)

    for disp, puntos in dispositivos.items():
        print(f"\n  Dispositivo: {disp}")
        print(f"  Registros  : {len(puntos)}")

        # Coordenadas únicas (redondeadas a 3 decimales ≈ 100m)
        ubicaciones_unicas = set(
            (round(p["lat"], 3), round(p["lon"], 3)) for p in puntos
        )
        print(f"  Ubicaciones distintas (±100m): {len(ubicaciones_unicas)}")

        # Timeline
        print(f"\n  Timeline de movimientos:")
        puntos_ord = sorted(puntos, key=lambda x: x["timestamp"])
        for p in puntos_ord:
            ts = p["timestamp"].replace("T", " ").replace("Z", " UTC")
            print(f"    {ts}  →  Lat: {p['lat']:.4f}, Lon: {p['lon']:.4f}  "
                  f"(±{p.get('precision_m', '?')}m)")

        # Correlación temporal con evento de interés
        evento_objetivo = "2026-03-15T08:23:00Z"
        ts_obj = datetime.fromisoformat(evento_objetivo.replace("Z", "+00:00"))
        print(f"\n  Correlación con evento de interés: {evento_objetivo}")
        for p in puntos_ord:
            ts_p = datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00"))
            delta = abs((ts_p - ts_obj).total_seconds()) / 60
            if delta <= 30:
                print(f"    ✔ A {delta:.0f} min del evento → "
                      f"Lat: {p['lat']:.4f}, Lon: {p['lon']:.4f}")


# ---------------------------------------------------------------------------
# PUNTO DE ENTRADA
# ---------------------------------------------------------------------------

def main():
    if "--generar-demo" in sys.argv:
        generar_demos()
        return

    if len(sys.argv) < 2:
        print("Uso: python json_forense.py <fichero.json> [--tipo actividad|geo]")
        print("     python json_forense.py --generar-demo")
        sys.exit(1)

    ruta = Path(sys.argv[1])
    if not ruta.exists():
        print(f"[ERROR] Fichero no encontrado: {ruta}")
        sys.exit(1)

    # Preservar integridad: calcular hash antes de leer
    sha256 = hashlib.sha256(ruta.read_bytes()).hexdigest()
    print(f"\n  [INTEGRIDAD] SHA-256: {sha256}")

    with open(ruta, "r", encoding="utf-8") as f:
        datos = json.load(f)

    tipo = "actividad"
    if "--tipo" in sys.argv:
        idx = sys.argv.index("--tipo")
        if idx + 1 < len(sys.argv):
            tipo = sys.argv[idx + 1]

    if tipo == "actividad":
        analizar_actividad(datos)
    elif tipo == "geo":
        analizar_geo(datos)
    else:
        print(f"[ERROR] Tipo desconocido: {tipo}. Usa 'actividad' o 'geo'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
