#!/usr/bin/env python3
"""
crypto_trace.py
===============
EJERCICIO EXTRA J2-B — Jornada 2: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Trazado forense de transacciones Bitcoin usando la API pública de
blockchain.info. Permite "seguir el dinero" a partir de una
dirección sospechosa.

Técnicas aplicadas:
  1. Consulta de balance e historial de transacciones de una dirección.
  2. Trazado de hasta N saltos (wallet hopping): seguir los fondos
     a través de múltiples direcciones intermedias.
  3. Detección de patrones sospechosos:
     - Transacciones a conocidos mixers/tumblers
     - Actividad nocturna
     - Dispersión de fondos (peeling chain)
  4. Exportación de grafo de transacciones a CSV.
  5. Modo OFFLINE con datos simulados para usar sin internet.

Caso real:
  En el ejercicio de Discord encontramos una wallet Bitcoin en los
  mensajes: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
  Ahora vamos a rastrear adónde fue ese dinero.

Uso
---
    # Modo demo (offline, sin internet)
    python crypto_trace.py --demo

    # Consultar dirección real (requiere internet)
    python crypto_trace.py --address <bitcoin_address>

    # Trazar saltos (requiere internet)
    python crypto_trace.py --address <bitcoin_address> --saltos 2

Dependencias
------------
    pip install requests   (solo para modo online)
    Modo offline: solo librería estándar

Autor   : Sergio M.
Versión : 1.0
Fecha   : 2026-04-10
"""

import sys
import json
import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

try:
    import urllib.request
    import urllib.error
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


DEMO_DATA = {
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": {
        "address":        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "final_balance":  0,
        "total_received": 8000000,   # en satoshis (0.08 BTC)
        "total_sent":     8000000,
        "n_tx":           3,
        "txs": [
            {
                "hash":        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "time":        1742068800,   # 2026-03-16T00:00:00Z
                "result":      8000000,      # recibidos
                "inputs":  [{"prev_out": {"addr": "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf", "value": 8000000}}],
                "out":    [{"addr": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "value": 8000000}],
            },
            {
                "hash":        "b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3",
                "time":        1742072400,   # 2026-03-16T01:00:00Z
                "result":      -4000000,
                "inputs":  [{"prev_out": {"addr": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "value": 4000000}}],
                "out":    [
                    {"addr": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5", "value": 3900000},  # mixer conocido
                    {"addr": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "value": 100000},  # cambio
                ],
            },
            {
                "hash":        "c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4",
                "time":        1742076000,   # 2026-03-16T02:00:00Z
                "result":      -4100000,
                "inputs":  [{"prev_out": {"addr": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "value": 4100000}}],
                "out":    [{"addr": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "value": 4050000}],
            },
        ]
    },
    "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5": {
        "address": "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5",
        "_nota":   "Dirección asociada a Wasabi Wallet (mixer/coinjoin)",
        "final_balance": 990000000,
        "total_received": 1234567890,
        "n_tx": 8831,
    }
}

# Direcciones conocidas de mixers / exchanges de alto riesgo
MIXERS_CONOCIDOS = {
    "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5": "Wasabi Wallet (CoinJoin mixer)",
    "bc1qazcm763354tsniqt4v5khkgrdjt6s3k9n3j9tr": "Chipmixer",
    "1CWHWkTWaq1K5hevmmHTcyGBOzVV7sHSoa": "BitcoinFog (shutdown)",
}


def satoshis_a_btc(sat: int) -> str:
    return f"{sat / 1e8:.8f} BTC"

def ts_a_utc(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def es_hora_sospechosa(ts: int) -> bool:
    hora = datetime.fromtimestamp(ts, tz=timezone.utc).hour
    return 0 <= hora < 6


def consultar_api(address: str) -> dict | None:
    """
    Consulta la API pública de Blockchain.info.
    No requiere API key para uso básico.
    """
    url = f"https://blockchain.info/rawaddr/{address}?limit=50"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  [!] HTTP {e.code}: {e.reason}")
        return None
    except Exception as e:
        print(f"  [!] Error de red: {e}")
        print(f"      Usa --demo para trabajar sin conexión.")
        return None


def analizar_direccion(address: str, data: dict, nivel: int = 0) -> list:
    """
    Analiza una dirección Bitcoin y devuelve lista de transacciones
    con hallazgos forenses.
    """
    prefijo = "  " * nivel

    print(f"\n{prefijo}{'─'*60}")
    print(f"{prefijo}  DIRECCIÓN: {address}")
    print(f"{prefijo}{'─'*60}")

    # Info de la dirección
    balance      = data.get("final_balance", 0)
    recibido     = data.get("total_received", 0)
    enviado      = data.get("total_sent", recibido - balance)
    n_tx         = data.get("n_tx", 0)
    nota_conocida = MIXERS_CONOCIDOS.get(address)

    print(f"{prefijo}  Balance actual : {satoshis_a_btc(balance)}")
    print(f"{prefijo}  Total recibido : {satoshis_a_btc(recibido)}")
    print(f"{prefijo}  Total enviado  : {satoshis_a_btc(enviado)}")
    print(f"{prefijo}  Transacciones  : {n_tx}")

    if nota_conocida:
        print(f"\n{prefijo}  🔴 DIRECCIÓN IDENTIFICADA: {nota_conocida}")
        print(f"{prefijo}     Los fondos han pasado por un servicio de mezcla.")
        print(f"{prefijo}     Objetivo: romper la trazabilidad en la blockchain.")

    hallazgos = []
    txs = data.get("txs", [])

    if not txs:
        return hallazgos

    print(f"\n{prefijo}  TRANSACCIONES:")
    print(f"{prefijo}  {'FECHA (UTC)':<24} {'HASH':<16} {'IMPORTE':<20} NOTAS")
    print(f"{prefijo}  {'─'*24} {'─'*16} {'─'*20} {'─'*20}")

    for tx in txs:
        ts      = tx.get("time", 0)
        h       = tx.get("hash", "?")[:12] + "..."
        importe = tx.get("result", 0)
        fecha   = ts_a_utc(ts) if ts else "N/A"

        notas = []
        if es_hora_sospechosa(ts):
            notas.append("🌙 nocturna")

        # Detectar direcciones destino conocidas
        for salida in tx.get("out", []):
            addr_dest = salida.get("addr", "")
            if addr_dest in MIXERS_CONOCIDOS:
                notas.append(f"⚠️  mixer: {MIXERS_CONOCIDOS[addr_dest]}")
            if addr_dest != address and addr_dest:
                hallazgos.append({
                    "origen": address,
                    "destino": addr_dest,
                    "btc": satoshis_a_btc(salida.get("value", 0)),
                    "timestamp_utc": fecha,
                    "tx_hash": tx.get("hash", ""),
                    "alerta": ", ".join(notas) if notas else "",
                })

        signo = "+" if importe >= 0 else ""
        print(f"{prefijo}  {fecha:<24} {h:<16} {signo}{satoshis_a_btc(abs(importe)):<20} {' | '.join(notas)}")

    return hallazgos


def trazar_saltos(address: str, max_saltos: int = 2, offline: bool = False) -> None:
    """
    Traza el flujo de fondos a través de múltiples saltos de wallet,
    construyendo el grafo de transacciones.
    """
    print("\n" + "="*65)
    print("  TRAZADO FORENSE DE TRANSACCIONES BITCOIN")
    print("="*65)
    print(f"\n  Dirección inicial : {address}")
    print(f"  Saltos máximos    : {max_saltos}")
    print(f"  Modo              : {'OFFLINE (demo)' if offline else 'ONLINE (blockchain.info)'}")

    visitadas = set()
    cola = [(address, 0)]
    todos_hallazgos = []

    while cola:
        addr_actual, nivel = cola.pop(0)
        if addr_actual in visitadas or nivel > max_saltos:
            continue
        visitadas.add(addr_actual)

        # Obtener datos
        if offline:
            data = DEMO_DATA.get(addr_actual)
            if not data:
                print(f"\n{'  '*nivel}  [offline] No hay datos demo para: {addr_actual[:20]}...")
                continue
        else:
            print(f"\n  Consultando: {addr_actual[:30]}...")
            data = consultar_api(addr_actual)
            if not data:
                continue

        hallazgos = analizar_direccion(addr_actual, data, nivel)
        todos_hallazgos.extend(hallazgos)

        # Encolar siguientes saltos
        if nivel < max_saltos:
            for h in hallazgos:
                dest = h["destino"]
                if dest not in visitadas:
                    cola.append((dest, nivel + 1))

    # Exportar grafo
    if todos_hallazgos:
        csv_path = "bitcoin_grafo.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            campos = ["origen", "destino", "btc", "timestamp_utc", "tx_hash", "alerta"]
            writer = csv.DictWriter(f, fieldnames=campos)
            writer.writeheader()
            writer.writerows(todos_hallazgos)

        print(f"\n  [+] Grafo exportado → {csv_path}")
        print(f"      Aristas (transferencias): {len(todos_hallazgos)}")
        print(f"      Nodos (direcciones):       {len(visitadas)}")

        alertas = [h for h in todos_hallazgos if h["alerta"]]
        if alertas:
            print(f"\n  ⚠️  Alertas detectadas: {len(alertas)}")
            for a in alertas:
                print(f"    {a['timestamp_utc']} | {a['origen'][:16]}... → {a['destino'][:16]}...")
                print(f"    {a['btc']} | {a['alerta']}")

    print("\n" + "="*65)
    print("  Próximos pasos en una investigación real:")
    print("  1. Solicitar info KYC del exchange donde se convirtió a fiat.")
    print("  2. Cruzar timestamps de BTC con actividad Discord/logs.")
    print("  3. Usar Chainalysis / CipherTrace para rastreo avanzado.")
    print("="*65)


def main():
    args = sys.argv[1:]

    if "--demo" in args or len(args) == 0:
        address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        print(f"\n  🎯 Dirección encontrada en los mensajes de Discord:")
        print(f"     {address}")
        print(f"\n  Esta dirección recibió el pago por la base de datos robada de ACME.")
        print(f"  Vamos a rastrear adónde fue ese dinero...")
        trazar_saltos(address, max_saltos=2, offline=True)
        return

    address = None
    if "--address" in args:
        address = args[args.index("--address") + 1]

    saltos = 1
    if "--saltos" in args:
        saltos = int(args[args.index("--saltos") + 1])

    if not address:
        print("Uso: python crypto_trace.py --demo")
        print("     python crypto_trace.py --address <btc_address>")
        print("     python crypto_trace.py --address <btc_address> --saltos 2")
        sys.exit(1)

    trazar_saltos(address, max_saltos=saltos, offline=False)


if __name__ == "__main__":
    main()
