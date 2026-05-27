#!/usr/bin/env python3
"""
timestamps_forense.py
=====================
EJERCICIO 3 — Jornada 2: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Análisis forense de timestamps digitales. Cubre:
  - Conversión entre formatos de timestamp (Unix, Windows FILETIME,
    HFS+, ISO 8601, WebKit/Chrome)
  - Detección de timestomping (manipulación de marcas de tiempo)
  - Construcción de una línea de tiempo (timeline) forense
  - Exportación a CSV ordenado cronológicamente

Uso
---
    python timestamps_forense.py
    python timestamps_forense.py --demo-timeline

Dependencias
------------
    Sólo librería estándar (datetime, struct, pathlib, csv)

Autor   : Sergio M.
Versión : 1.0
Fecha   : 2026-04-10
"""

import sys
import csv
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path



# Windows FILETIME: intervalos de 100 nanosegundos desde 1601-01-01 UTC
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# HFS+ / Mac Absolute Time: segundos desde 1904-01-01
HFS_EPOCH = datetime(1904, 1, 1, tzinfo=timezone.utc)
# WebKit / Chrome: microsegundos desde 1601-01-01 UTC (= FILETIME / 10)
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def unix_a_utc(ts: float) -> datetime:
    """Convierte Unix epoch (segundos) a datetime UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc)

def filetime_a_utc(ft: int) -> datetime:
    """
    Convierte Windows FILETIME a datetime UTC.
    FILETIME = intervalos de 100 ns desde 1601-01-01.
    Presente en: NTFS MFT, registros de Windows, Prefetch, LNK files.
    """
    microsegundos = ft // 10  # 100 ns → microsegundos
    return FILETIME_EPOCH + timedelta(microseconds=microsegundos)

def hfs_a_utc(ts: int) -> datetime:
    """
    Convierte timestamp HFS+ a datetime UTC.
    Segundos desde 1904-01-01. Presente en: sistemas macOS, iPhone backups.
    """
    return HFS_EPOCH + timedelta(seconds=ts)

def webkit_a_utc(ts: int) -> datetime:
    """
    Convierte timestamp WebKit (Chrome) a datetime UTC.
    Microsegundos desde 1601-01-01. Presente en: History, Cookies de Chrome.
    """
    return WEBKIT_EPOCH + timedelta(microseconds=ts)

def utc_a_unix(dt: datetime) -> float:
    """Convierte datetime UTC a Unix epoch."""
    return dt.timestamp()

def utc_a_filetime(dt: datetime) -> int:
    """Convierte datetime UTC a Windows FILETIME."""
    delta = dt - FILETIME_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def demo_conversiones():
    """Muestra conversiones entre formatos con ejemplos reales del caso."""
    print("\n" + "="*65)
    print("  CONVERSIÓN DE FORMATOS DE TIMESTAMP")
    print("="*65)

    ejemplos = [
        ("Unix epoch",      "unix",     1742031200.0),
        ("Windows FILETIME","filetime", 133879855200000000),
        ("HFS+ / macOS",    "hfs",      3857558400),
        ("WebKit / Chrome", "webkit",   13379398800000000),
    ]

    print(f"\n  {'Formato':<22} {'Valor original':<26} {'UTC legible'}")
    print(f"  {'-'*22} {'-'*26} {'-'*30}")

    for nombre, tipo, valor in ejemplos:
        if tipo == "unix":
            dt = unix_a_utc(valor)
        elif tipo == "filetime":
            dt = filetime_a_utc(valor)
        elif tipo == "hfs":
            dt = hfs_a_utc(valor)
        elif tipo == "webkit":
            dt = webkit_a_utc(valor)

        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"  {nombre:<22} {str(valor):<26} {dt_str}")

    # Conversión inversa: fecha → FILETIME (útil para buscar en volcados binarios)
    fecha_interes = datetime(2026, 3, 15, 8, 23, 0, tzinfo=timezone.utc)
    ft = utc_a_filetime(fecha_interes)
    print(f"\n  Conversión inversa:")
    print(f"  {fecha_interes.isoformat()} → FILETIME: {ft}")
    print(f"  → En hex (little-endian): {ft.to_bytes(8, 'little').hex()}")
    print(f"    (Útil para buscar en volcados de memoria con strings binarios)")


def detectar_timestomping(ruta: str) -> None:
    """
    Detecta posible timestomping (manipulación de timestamps) en un fichero.
    Compara MAC times (Modified, Accessed, Changed) para detectar
    inconsistencias que revelan manipulación.
    """
    p = Path(ruta)
    if not p.exists():
        print(f"[ERROR] No existe: {ruta}")
        return

    stat = p.stat()
    ts_modificacion = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    ts_acceso       = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc)
    ts_cambio_meta  = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)

    print(f"\n  Archivo  : {p.name}")
    print(f"  Modificado (mtime) : {ts_modificacion.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Accedido  (atime)  : {ts_acceso.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Metadatos (ctime)  : {ts_cambio_meta.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    alertas = []

    # Regla 1: mtime anterior a ctime (imposible en condiciones normales)
    if ts_modificacion < ts_cambio_meta - timedelta(seconds=2):
        alertas.append(
            "mtime < ctime: el archivo fue modificado ANTES de que cambiaran "
            "sus metadatos — posible timestomping hacia atrás"
        )

    # Regla 2: timestamps con segundos exactos (herramientas de timestomping
    # suelen poner valores redondos: :00, :30)
    if ts_modificacion.second == 0 and ts_modificacion.microsecond == 0:
        alertas.append(
            "mtime con segundos exactos (:00.000000) — patrón frecuente "
            "en timestamps fabricados con herramientas forenses ofensivas"
        )

    # Regla 3: fecha anómalamente antigua para el tipo de archivo
    umbral_antiguo = datetime(2000, 1, 1, tzinfo=timezone.utc)
    if ts_modificacion < umbral_antiguo:
        alertas.append(
            f"mtime ({ts_modificacion.year}) anterior al año 2000 — "
            "probable manipulación para ocultar fecha real"
        )

    if alertas:
        print(f"\n  ⚠️  Indicadores de timestomping detectados:")
        for a in alertas:
            print(f"    • {a}")
    else:
        print(f"\n  ✔ No se detectaron indicadores obvios de timestomping")



EVENTOS_DEMO = [
    {"fuente": "FileSystem",  "tipo": "FILE_CREATE",  "timestamp_utc": "2026-03-15T08:21:00Z", "descripcion": "clientes_db_export.csv creado en C:\\Users\\jperez\\Desktop"},
    {"fuente": "FileSystem",  "tipo": "FILE_ACCESS",  "timestamp_utc": "2026-03-15T08:25:00Z", "descripcion": "nominas_2026.xlsx accedido por proceso OUTLOOK.EXE"},
    {"fuente": "AppLog",      "tipo": "USER_ACTION",  "timestamp_utc": "2026-03-15T08:23:11Z", "descripcion": "jperez autenticado en aplicación Correo desde 192.168.1.45"},
    {"fuente": "AppLog",      "tipo": "FILE_UPLOAD",  "timestamp_utc": "2026-03-15T08:27:45Z", "descripcion": "clientes_db_export.csv subido a drive.externo.com"},
    {"fuente": "NetworkLog",  "tipo": "DNS_QUERY",    "timestamp_utc": "2026-03-15T08:27:30Z", "descripcion": "Resolución DNS: drive.externo.com → 185.100.22.10"},
    {"fuente": "NetworkLog",  "tipo": "TCP_CONNECT",  "timestamp_utc": "2026-03-15T08:27:44Z", "descripcion": "Conexión TCP saliente → 185.100.22.10:443"},
    {"fuente": "Registry",    "tipo": "REG_WRITE",    "timestamp_utc": "2026-03-15T02:15:22Z", "descripcion": "HKLM\\SOFTWARE\\permisos_usuarios modificado por admin"},
    {"fuente": "EventLog",    "tipo": "LOGON",        "timestamp_utc": "2026-03-15T02:14:00Z", "descripcion": "Logon interactivo: admin desde 185.220.101.45 (Tor)"},
    {"fuente": "EventLog",    "tipo": "LOGOFF",       "timestamp_utc": "2026-03-15T02:16:00Z", "descripcion": "Logoff: admin"},
    {"fuente": "SQLite",      "tipo": "MSG_SENT",     "timestamp_utc": "2026-03-15T08:26:00Z", "descripcion": "Mensaje enviado a Número Oculto (+447890123456): 'Confirma recepción'"},
]

def construir_timeline(eventos: list) -> None:
    """Ordena eventos de múltiples fuentes y construye una timeline forense."""
    print("\n" + "="*65)
    print("  TIMELINE FORENSE — VISIÓN INTEGRADA")
    print("="*65)

    # Ordenar por timestamp
    def parse_ts(e):
        return datetime.fromisoformat(e["timestamp_utc"].replace("Z", "+00:00"))

    eventos_ord = sorted(eventos, key=parse_ts)

    print(f"\n  {len(eventos_ord)} eventos de {len(set(e['fuente'] for e in eventos_ord))} fuentes\n")
    print(f"  {'TIMESTAMP (UTC)':<24} {'FUENTE':<14} {'TIPO':<15} DESCRIPCIÓN")
    print(f"  {'-'*24} {'-'*14} {'-'*15} {'-'*35}")

    for e in eventos_ord:
        ts = parse_ts(e).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {ts:<24} {e['fuente']:<14} {e['tipo']:<15} {e['descripcion'][:60]}")

    # Exportar
    csv_path = "timeline_forense.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        campos = ["timestamp_utc", "fuente", "tipo", "descripcion"]
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        for e in eventos_ord:
            writer.writerow(e)

    print(f"\n  [+] Timeline exportada → {csv_path}")
    print(f"\n  Ventana de actividad sospechosa detectada:")
    print(f"    02:14 – 02:16 UTC  →  Acceso admin desde Tor, modificación de permisos")
    print(f"    08:23 – 08:27 UTC  →  Descarga y exfiltración de ficheros sensibles")

def main():
    print("\n" + "="*65)
    print("  HERRAMIENTA DE ANÁLISIS DE TIMESTAMPS FORENSES")
    print("="*65)

    demo_conversiones()

    print("\n" + "-"*65)
    print("  DETECCIÓN DE TIMESTOMPING")
    print("-"*65)

    # Analizar el propio script como ejemplo
    detectar_timestomping(__file__)

    if "--demo-timeline" in sys.argv or True:
        construir_timeline(EVENTOS_DEMO)


if __name__ == "__main__":
    main()
