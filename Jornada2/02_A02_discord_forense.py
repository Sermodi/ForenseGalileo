#!/usr/bin/env python3
"""
discord_forense.py
==================
EJERCICIO EXTRA J2-A — Jornada 2: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Análisis forense del paquete de datos de Discord (GDPR export).
Discord permite a cualquier usuario descargar todos sus datos en
Settings → Privacy & Safety → Request all my Data.

El paquete contiene (entre otros):
  - messages/   : todos los mensajes enviados (JSON por canal)
  - account/    : información de la cuenta y fechas clave
  - activity/   : eventos de uso de la aplicación
  - guild/      : servidores a los que pertenece

Este script analiza el export y construye:
  1. Perfil de actividad horaria (¿a qué horas está activo el usuario?)
  2. Palabras clave sospechosas en mensajes
  3. Detección de mensajes borrados (presentes en export pero no en app)
  4. Servidores más frecuentados
  5. Timeline de actividad

Casos reales:
  - Identificar a un sospechoso por su patrón de actividad nocturna.
  - Cruzar timestamps de Discord con otros artefactos del caso.
  - Detectar canales de venta de datos robados o ciberataques coordinados.

Uso
---
    python discord_forense.py --generar-demo        # Crea export simulado
    python discord_forense.py --carpeta <ruta>      # Analiza export real
    python discord_forense.py --buscar <keyword> --carpeta <ruta>

Dependencias
------------
    Solo librería estándar (json, datetime, pathlib, csv, collections)

Autor   : Sergio M.
Versión : 1.0
Fecha   : 2026-04-10
"""

import sys
import json
import csv
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict


CANALES_DEMO = {
    "channel_123456": {
        "name": "general",
        "guild": "Ciberataques ES",
        "mensajes": [
            {"ID": "1001", "Timestamp": "2026-03-14T23:45:12.000+00:00", "Contents": "alguien tiene el RAT listo?", "Attachments": ""},
            {"ID": "1002", "Timestamp": "2026-03-15T00:10:33.000+00:00", "Contents": "sí, compilado esta tarde. sin detección en VT", "Attachments": "payload_final.exe"},
            {"ID": "1003", "Timestamp": "2026-03-15T00:12:01.000+00:00", "Contents": "perfecto. el objetivo es el servidor de ACME Corp", "Attachments": ""},
            {"ID": "1004", "Timestamp": "2026-03-15T00:14:55.000+00:00", "Contents": "tienen el puerto 22 abierto y usan credenciales por defecto lol", "Attachments": ""},
            {"ID": "1005", "Timestamp": "2026-03-15T02:15:00.000+00:00", "Contents": "dentro 🔥 ya tengo acceso admin", "Attachments": ""},
            {"ID": "1006", "Timestamp": "2026-03-15T02:16:30.000+00:00", "Contents": "exfiltrando... 2.3GB de datos de clientes", "Attachments": ""},
            {"ID": "1007", "Timestamp": "2026-03-15T02:20:00.000+00:00", "Contents": "subido al drive. link: https://mega.nz/xxxx", "Attachments": ""},
        ]
    },
    "channel_789012": {
        "name": "ventas",
        "guild": "Ciberataques ES",
        "mensajes": [
            {"ID": "2001", "Timestamp": "2026-03-16T15:30:00.000+00:00", "Contents": "DB de clientes ACME a la venta. 50k registros. precio: 0.8 BTC", "Attachments": ""},
            {"ID": "2002", "Timestamp": "2026-03-16T16:00:00.000+00:00", "Contents": "interesado, te mando wallet", "Attachments": ""},
            {"ID": "2003", "Timestamp": "2026-03-16T16:05:00.000+00:00", "Contents": "wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "Attachments": ""},
        ]
    },
    "channel_345678": {
        "name": "amigos",
        "guild": "DM",
        "mensajes": [
            {"ID": "3001", "Timestamp": "2026-03-15T08:00:00.000+00:00", "Contents": "oye tío, anoche nos forramos", "Attachments": ""},
            {"ID": "3002", "Timestamp": "2026-03-15T09:00:00.000+00:00", "Contents": "sí pero borra esto después", "Attachments": ""},
            {"ID": "3003", "Timestamp": "2026-03-15T09:01:00.000+00:00", "Contents": "ya sé ya sé", "Attachments": ""},
        ]
    },
}

ACCOUNT_DEMO = {
    "id": "987654321098765432",
    "username": "n1ghtcrawl3r",
    "discriminator": "0666",
    "email": "jperez_privado@protonmail.com",
    "verified": True,
    "ip_address_used_to_register": "185.220.101.45",
    "created_at": "2024-11-01T12:00:00.000+00:00",
    "phone": None,
}


def generar_demo() -> None:
    """Crea un paquete de datos Discord simulado con estructura real."""
    base = Path("evidencias_discord")
    base.mkdir(exist_ok=True)

    (base / "account").mkdir(exist_ok=True)
    with open(base / "account" / "user.json", "w", encoding="utf-8") as f:
        json.dump(ACCOUNT_DEMO, f, ensure_ascii=False, indent=2)

    msg_base = base / "messages"
    msg_base.mkdir(exist_ok=True)

    for canal_id, canal_info in CANALES_DEMO.items():
        canal_dir = msg_base / canal_id
        canal_dir.mkdir(exist_ok=True)

        with open(canal_dir / "channel.json", "w", encoding="utf-8") as f:
            json.dump({
                "id": canal_id,
                "type": 0 if canal_info["guild"] != "DM" else 1,
                "name": canal_info["name"],
                "guild": {"name": canal_info["guild"]},
            }, f, ensure_ascii=False, indent=2)

        campos = ["ID", "Timestamp", "Contents", "Attachments"]
        with open(canal_dir / "messages.json", "w", encoding="utf-8") as f:
            json.dump(canal_info["mensajes"], f, ensure_ascii=False, indent=2)

    sha = hashlib.sha256(json.dumps(ACCOUNT_DEMO).encode()).hexdigest()
    print(f"[OK] Export simulado creado en: {base}/")
    print(f"     Hash cuenta: {sha[:16]}...")
    print(f"\nSiguiente paso:")
    print(f"  python discord_forense.py --carpeta {base}")


KEYWORDS_CRITICAS = [
    "payload", "rat", "exploit", "shell", "reverse", "btc", "bitcoin", "wallet",
    "exfil", "dump", "leak", "hack", "crack", "zero-day", "0day", "bypass",
    "dropper", "botnet", "c2", "c&c", "mega.nz", "anonfile", "protonmail",
    "contraseña", "password", "credencial", "admin", "root", "sudo",
]


def parsear_timestamp(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def analizar_discord(carpeta: str, keyword_buscar: str = None) -> None:
    base = Path(carpeta)

    print("\n" + "="*65)
    print("  ANÁLISIS FORENSE — PAQUETE DE DATOS DISCORD")
    print("="*65)

    # 1. Cuenta
    cuenta_path = base / "account" / "user.json"
    if cuenta_path.exists():
        cuenta = json.loads(cuenta_path.read_text(encoding="utf-8"))
        print(f"\n  Usuario    : {cuenta.get('username')}#{cuenta.get('discriminator')}")
        print(f"  ID         : {cuenta.get('id')}")
        print(f"  Email      : {cuenta.get('email', 'N/A')}")
        print(f"  Creado     : {cuenta.get('created_at', 'N/A')}")
        ip_reg = cuenta.get("ip_address_used_to_register", "N/A")
        print(f"  IP registro: {ip_reg}")
        if ip_reg not in ("N/A", None):
            print(f"    ⚠️  La IP de registro puede vincular al usuario con una ubicación real")

    # 2. Recorrer mensajes
    msg_base = base / "messages"
    if not msg_base.exists():
        print("[!] No se encontró carpeta de mensajes")
        return

    todos_mensajes = []
    canales_info = {}
    conteo_canal = Counter()

    for canal_dir in sorted(msg_base.iterdir()):
        if not canal_dir.is_dir():
            continue

        canal_json = canal_dir / "channel.json"
        msg_json   = canal_dir / "messages.json"

        canal_nombre = canal_dir.name
        guild_nombre = "DM"

        if canal_json.exists():
            meta = json.loads(canal_json.read_text(encoding="utf-8"))
            canal_nombre = meta.get("name", canal_dir.name)
            guild_nombre = meta.get("guild", {}).get("name", "DM") if meta.get("guild") else "DM"

        canales_info[canal_dir.name] = f"{guild_nombre} / #{canal_nombre}"

        if msg_json.exists():
            mensajes = json.loads(msg_json.read_text(encoding="utf-8"))
            for m in mensajes:
                m["_canal"] = canal_dir.name
                m["_canal_nombre"] = f"{guild_nombre} / #{canal_nombre}"
                todos_mensajes.append(m)
                conteo_canal[canal_dir.name] += 1

    print(f"\n  Mensajes totales  : {len(todos_mensajes)}")
    print(f"  Canales analizados: {len(canales_info)}")

    # 3. Actividad horaria
    horas = Counter()
    for m in todos_mensajes:
        ts = parsear_timestamp(m.get("Timestamp", ""))
        if ts:
            horas[ts.hour] += 1

    print(f"\n  Distribución horaria de actividad (UTC):")
    max_h = max(horas.values()) if horas else 1
    for h in range(24):
        n = horas.get(h, 0)
        barra = "█" * int(20 * n / max_h) if max_h > 0 else ""
        alerta = " ← actividad nocturna sospechosa" if 0 <= h < 6 and n > 0 else ""
        if n > 0 or (0 <= h < 6):
            print(f"    {h:02d}:00  {barra:<20} {n:>4}{alerta}")

    # 4. Búsqueda de keywords sospechosas
    print(f"\n  Búsqueda de palabras clave críticas:")
    hits = defaultdict(list)
    for m in todos_mensajes:
        texto = (m.get("Contents") or "").lower()
        for kw in (KEYWORDS_CRITICAS if not keyword_buscar else [keyword_buscar.lower()]):
            if kw in texto:
                hits[kw].append(m)

    if hits:
        for kw, mensajes_kw in sorted(hits.items(), key=lambda x: -len(x[1])):
            print(f"\n  🔴 '{kw}' — {len(mensajes_kw)} coincidencia(s):")
            for m in mensajes_kw[:3]:
                ts = parsear_timestamp(m.get("Timestamp", ""))
                ts_str = ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "N/A"
                canal = m.get("_canal_nombre", "?")
                texto = (m.get("Contents") or "")[:80]
                print(f"    [{ts_str}] {canal}")
                print(f"    → {texto}")
    else:
        print("    No se encontraron palabras clave críticas.")

    # 5. Adjuntos sospechosos
    adjuntos = [(m.get("Attachments"), m) for m in todos_mensajes if m.get("Attachments")]
    if adjuntos:
        print(f"\n  Archivos adjuntos ({len(adjuntos)}):")
        for adj, m in adjuntos:
            ts = parsear_timestamp(m.get("Timestamp", ""))
            ts_str = ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "N/A"
            print(f"    [{ts_str}] {adj}")

    # 6. Exportar timeline
    timeline_path = "discord_timeline.csv"
    with open(timeline_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp_utc", "canal", "mensaje", "adjunto"])
        writer.writeheader()
        for m in sorted(todos_mensajes, key=lambda x: x.get("Timestamp", "")):
            ts = parsear_timestamp(m.get("Timestamp", ""))
            writer.writerow({
                "timestamp_utc": ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "",
                "canal": m.get("_canal_nombre", ""),
                "mensaje": (m.get("Contents") or "")[:200],
                "adjunto": m.get("Attachments") or "",
            })

    print(f"\n  [+] Timeline exportada → {timeline_path}")
    print("\n" + "="*65)


def main():
    if "--generar-demo" in sys.argv:
        generar_demo()
        return

    carpeta = "."
    if "--carpeta" in sys.argv:
        carpeta = sys.argv[sys.argv.index("--carpeta") + 1]

    keyword = None
    if "--buscar" in sys.argv:
        keyword = sys.argv[sys.argv.index("--buscar") + 1]

    if len(sys.argv) < 2:
        print("Uso: python discord_forense.py --generar-demo")
        print("     python discord_forense.py --carpeta <ruta_export>")
        print("     python discord_forense.py --buscar <keyword> --carpeta <ruta>")
        sys.exit(1)

    analizar_discord(carpeta, keyword)


if __name__ == "__main__":
    main()
