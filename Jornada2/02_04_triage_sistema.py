#!/usr/bin/env python3
"""
triage_sistema.py
=================
EJERCICIO 4 — Jornada 2: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Triage rápido de un sistema en vivo: captura el estado volátil
del sistema antes de que se pierda al apagarlo. Cubre:
  - Procesos en ejecución (PID, nombre, usuario, red)
  - Conexiones de red activas
  - Usuarios con sesión iniciada
  - Ficheros abiertos por proceso sospechoso
  - Exportación firmada del snapshot (hash SHA-256)

Uso
---
    python triage_sistema.py
    python triage_sistema.py --proceso <nombre_o_pid>
    python triage_sistema.py --exportar

⚠️  En un triage real: ejecutar SIEMPRE antes de tocar nada.
    Los datos de memoria y red son VOLÁTILES — desaparecen al reiniciar.

Dependencias
------------
    pip install psutil

Autor   : SergioM.
Versión : 1.0
Fecha   : 2026-04-10
"""

import sys
import csv
import json
import hashlib
import platform
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    print("\n[ERROR] psutil no está instalado.")
    print("        Instálalo con: pip install psutil\n")
    sys.exit(1)


TS_INICIO = datetime.now(tz=timezone.utc)
TS_STR    = TS_INICIO.strftime("%Y%m%d_%H%M%S")


def info_sistema() -> dict:
    """Captura información básica del sistema operativo."""
    try:
        arranque = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        arranque_str = arranque.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        arranque_str = "N/A"

    return {
        "hostname":    platform.node(),
        "so":          f"{platform.system()} {platform.release()}",
        "arquitectura": platform.machine(),
        "python":      platform.python_version(),
        "arranque":    arranque_str,
        "triage_utc":  TS_INICIO.strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

# Procesos típicamente legítimos — lista simplificada para el ejercicio
PROCESOS_RUIDO = {
    "system", "svchost.exe", "csrss.exe", "smss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "explorer.exe",
    "python.exe", "python3", "python", "bash", "sh",
}

def listar_procesos(solo_interesantes: bool = False) -> list:
    """
    Enumera todos los procesos activos con sus atributos forenses clave.
    Si solo_interesantes=True, filtra los procesos de sistema habituales.
    """
    procesos = []
    for proc in psutil.process_iter([
        "pid", "name", "username", "status",
        "create_time", "cmdline", "exe", "ppid",
    ]):
        try:
            info = proc.info
            nombre = info.get("name") or ""

            if solo_interesantes and nombre.lower() in PROCESOS_RUIDO:
                continue

            ts_creacion = ""
            if info.get("create_time"):
                ts_creacion = datetime.fromtimestamp(
                    info["create_time"], tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC")

            cmdline = " ".join(info.get("cmdline") or [])[:120]

            procesos.append({
                "pid":        info.get("pid"),
                "ppid":       info.get("ppid"),
                "nombre":     nombre,
                "usuario":    info.get("username") or "N/A",
                "estado":     info.get("status") or "N/A",
                "inicio":     ts_creacion,
                "exe":        info.get("exe") or "N/A",
                "cmdline":    cmdline,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return procesos


PUERTOS_SOSPECHOSOS = {
    4444, 1337, 31337, 9999, 8888,  # shells inversas clásicas
    6667, 6697,                       # IRC (botnets)
}

def listar_conexiones() -> list:
    """
    Captura conexiones TCP/UDP activas y señala puertos sospechosos.
    En un triage real, esta información es crítica — refleja actividad
    de red en el momento exacto de la captura.
    """
    conexiones = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

            # Nombre del proceso asociado
            nombre_proc = "N/A"
            try:
                if conn.pid:
                    nombre_proc = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            alerta = ""
            if conn.raddr and conn.raddr.port in PUERTOS_SOSPECHOSOS:
                alerta = "PUERTO_SOSPECHOSO"

            conexiones.append({
                "pid":       conn.pid,
                "proceso":   nombre_proc,
                "tipo":      conn.type.name if hasattr(conn.type, "name") else str(conn.type),
                "local":     laddr,
                "remoto":    raddr,
                "estado":    conn.status,
                "alerta":    alerta,
            })
    except psutil.AccessDenied:
        print("  [!] Acceso denegado a conexiones de red — ejecutar con privilegios elevados")

    return conexiones


def listar_usuarios() -> list:
    """Lista usuarios con sesión iniciada en el sistema."""
    usuarios = []
    for u in psutil.users():
        ts = datetime.fromtimestamp(u.started, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        usuarios.append({
            "usuario":   u.name,
            "terminal":  u.terminal or "N/A",
            "host":      u.host or "local",
            "inicio":    ts,
        })
    return usuarios


def ficheros_proceso(identificador) -> None:
    """
    Lista los ficheros abiertos por un proceso dado (PID o nombre).
    Útil para identificar qué datos está leyendo/escribiendo un proceso
    sospechoso en el momento del triage.
    """
    proc_obj = None
    try:
        pid = int(identificador)
        proc_obj = psutil.Process(pid)
    except ValueError:
        # Es un nombre, buscar por nombre
        for p in psutil.process_iter(["name"]):
            if p.info["name"] and identificador.lower() in p.info["name"].lower():
                proc_obj = p
                break

    if not proc_obj:
        print(f"  [!] Proceso no encontrado: {identificador}")
        return

    print(f"\n  Proceso: {proc_obj.name()} (PID {proc_obj.pid})")
    print(f"  Ficheros abiertos:")
    try:
        ficheros = proc_obj.open_files()
        if ficheros:
            for f in ficheros:
                print(f"    {f.path}")
        else:
            print("    (Sin ficheros abiertos o acceso denegado)")
    except psutil.AccessDenied:
        print("    [!] Acceso denegado — necesitas privilegios de administrador")


def exportar_snapshot() -> None:
    """
    Genera un snapshot JSON del estado del sistema, firmado con SHA-256.
    Este fichero puede usarse como evidencia del estado del sistema
    en el momento exacto del triage.
    """
    nombre = f"triage_{TS_STR}.json"

    snapshot = {
        "meta": {
            "herramienta":  "triage_sistema.py — GalileoForense",
            "version":      "1.0",
            "triage_utc":   TS_STR,
        },
        "sistema":    info_sistema(),
        "procesos":   listar_procesos(),
        "conexiones": listar_conexiones(),
        "usuarios":   listar_usuarios(),
    }

    contenido = json.dumps(snapshot, ensure_ascii=False, indent=2)
    sha256 = hashlib.sha256(contenido.encode("utf-8")).hexdigest()
    snapshot["meta"]["sha256_snapshot"] = sha256

    with open(nombre, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)

    print(f"\n  [+] Snapshot exportado  → {nombre}")
    print(f"      SHA-256              : {sha256}")
    print(f"      Procesos capturados  : {len(snapshot['procesos'])}")
    print(f"      Conexiones capturadas: {len(snapshot['conexiones'])}")
    print(f"\n  ⚠️  Guarda el SHA-256 en tu informe pericial para demostrar")
    print(f"      que el snapshot no fue alterado después de la captura.")


def mostrar_resumen() -> None:
    """Muestra el resumen de triage en consola de forma legible."""
    print("\n" + "="*65)
    print("  TRIAGE DE SISTEMA — SNAPSHOT VOLÁTIL")
    print("="*65)

    # Sistema
    sys_info = info_sistema()
    print(f"\n  Hostname    : {sys_info['hostname']}")
    print(f"  SO          : {sys_info['so']}")
    print(f"  Arranque    : {sys_info['arranque']}")
    print(f"  Triage UTC  : {sys_info['triage_utc']}")

    # Usuarios
    usuarios = listar_usuarios()
    print(f"\n  Usuarios activos: {len(usuarios)}")
    for u in usuarios:
        print(f"    {u['usuario']:<20} desde {u['host']:<16} ({u['inicio']})")

    # Procesos (top 15 más recientes, excluyendo ruido)
    procesos = listar_procesos(solo_interesantes=True)
    print(f"\n  Procesos destacados ({len(procesos)} excluidos sistema):")
    print(f"  {'PID':<7} {'NOMBRE':<25} {'USUARIO':<20} {'INICIO'}")
    print(f"  {'-'*7} {'-'*25} {'-'*20} {'-'*25}")
    for p in procesos[:15]:
        print(f"  {str(p['pid']):<7} {p['nombre']:<25} {p['usuario']:<20} {p['inicio']}")

    # Conexiones
    conexiones = listar_conexiones()
    activas = [c for c in conexiones if c["estado"] == "ESTABLISHED"]
    alertas = [c for c in conexiones if c["alerta"]]
    print(f"\n  Conexiones de red: {len(conexiones)} total | {len(activas)} ESTABLISHED")

    if activas:
        print(f"\n  {'PROCESO':<20} {'LOCAL':<22} {'REMOTO':<22} ESTADO")
        print(f"  {'-'*20} {'-'*22} {'-'*22} {'-'*15}")
        for c in activas[:10]:
            print(f"  {c['proceso']:<20} {c['local']:<22} {c['remoto']:<22} {c['estado']}")

    if alertas:
        print(f"\n  ⚠️  Conexiones a puertos sospechosos:")
        for c in alertas:
            print(f"    PID {c['pid']} ({c['proceso']}) → {c['remoto']} [{c['alerta']}]")


def main():
    if "--proceso" in sys.argv:
        idx = sys.argv.index("--proceso")
        if idx + 1 < len(sys.argv):
            ficheros_proceso(sys.argv[idx + 1])
        else:
            print("[ERROR] --proceso requiere un nombre o PID")
        return

    mostrar_resumen()

    if "--exportar" in sys.argv:
        exportar_snapshot()
    else:
        print(f"\n  Tip: añade --exportar para guardar el snapshot en JSON firmado")


if __name__ == "__main__":
    main()
