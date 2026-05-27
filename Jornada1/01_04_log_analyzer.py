#!/usr/bin/env python3
"""
01_04_log_analyzer.py
=====================
EJERCICIO 4 - Jornada 1: Informatica Forense con Python
Formacion GalileoForense

Descripcion
-----------
Herramienta forense para parsear, filtrar y analizar archivos de log
del sistema. Detecta eventos criticos, IPs sospechosas y genera
un informe de anomalias.

Formato de log esperado
-----------------------
    YYYY-MM-DD HH:MM:SS NIVEL [MODULO] MENSAJE

    NIVEL  : INFO | WARN | ERROR
    MODULO : auth | net | file | usb | system

Uso
---
    python 01_04_log_analyzer.py <archivo_log> [opciones]

    Opciones:
      --top N         : Mostrar las N IPs mas frecuentes (default: 10)
      --nivel NIVEL   : Filtrar por nivel de log (INFO, WARN, ERROR)
      --ip IP         : Filtrar eventos que contengan la IP especificada
      --csv           : Exportar todos los eventos a log_analisis.csv
      --resumen       : Solo mostrar estadisticas, sin listar eventos

Ejemplos
--------
    python 01_04_log_analyzer.py sistema.log
    python 01_04_log_analyzer.py sistema.log --top 5
    python 01_04_log_analyzer.py sistema.log --nivel ERROR
    python 01_04_log_analyzer.py sistema.log --ip 185.220.101.45
    python 01_04_log_analyzer.py sistema.log --csv --resumen

Dataset de ejemplo
------------------
    Guardar el siguiente contenido en 'sistema.log' para las pruebas:

    2024-03-15 08:12:33 INFO  [auth]   Usuario admin ha iniciado sesion desde 192.168.1.101
    2024-03-15 08:15:44 INFO  [file]   Archivo /docs/contrato.docx abierto por admin
    2024-03-15 08:17:01 WARN  [net]    Conexion saliente a 185.220.101.45:443
    2024-03-15 08:17:05 ERROR [system] Fallo de acceso a /etc/shadow por usuario admin
    2024-03-15 08:22:18 INFO  [file]   Archivo /docs/contrato.docx copiado a /tmp/c.docx
    2024-03-15 08:25:50 WARN  [usb]    Dispositivo USB conectado: Vendor=0930 Product=6545
    2024-03-15 08:26:03 INFO  [file]   Archivo /tmp/c.docx copiado a /media/usb/c.docx
    2024-03-15 08:28:11 INFO  [auth]   Usuario admin ha cerrado sesion

Autor   : SergioM
Version : 2.0
Fecha   : 2026-04-05
"""

import os
import re
import sys
import csv
import datetime
from collections import Counter, defaultdict


# Patron principal: captura los 5 campos de cada linea del log.
# Grupos nombrados para facilitar su auditoria en procedimientos legales.
PATRON_LOG = re.compile(
    r"(?P<fecha>\d{4}-\d{2}-\d{2})"          # Fecha YYYY-MM-DD
    r"\s+(?P<hora>\d{2}:\d{2}:\d{2})"         # Hora HH:MM:SS
    r"\s+(?P<nivel>\w+)"                       # Nivel: INFO, WARN, ERROR
    r"\s+\[(?P<modulo>\w+)\]"                  # Modulo: [auth], [net], [file]...
    r"\s+(?P<mensaje>.+)"                      # Mensaje libre
)

# Patron secundario: extrae IPs del campo mensaje
PATRON_IP = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# IPs conocidas como nodos de salida Tor o fuentes maliciosas
# (en produccion, cargar desde lista actualizada como TorProject exit nodes)
IPS_SOSPECHOSAS = {
    "185.220.101.45": "Nodo de salida Tor conocido",
    "185.220.101.46": "Nodo de salida Tor conocido",
    "192.42.116.16":  "Nodo de salida Tor conocido",
}

class EventoLog:
    """
    Representa un evento parseado de una linea de log.

    Atributos
    ---------
    fecha     : str             Fecha del evento (YYYY-MM-DD).
    hora      : str             Hora del evento (HH:MM:SS).
    nivel     : str             Nivel: INFO, WARN, ERROR.
    modulo    : str             Modulo origen: auth, net, file, usb, system.
    mensaje   : str             Texto libre del evento.
    ips       : list[str]       IPs extraidas del mensaje.
    linea_raw : str             Linea original (preservada para el informe).
    timestamp : datetime | None Timestamp combinado para ordenacion.
    """

    def __init__(self, fecha: str, hora: str, nivel: str,
                 modulo: str, mensaje: str, linea_raw: str):
        self.fecha     = fecha
        self.hora      = hora
        self.nivel     = nivel.strip().upper()
        self.modulo    = modulo.strip().lower()
        self.mensaje   = mensaje.strip()
        self.linea_raw = linea_raw.strip()
        self.ips       = PATRON_IP.findall(self.mensaje)
        try:
            self.timestamp = datetime.datetime.strptime(
                f"{fecha} {hora}", "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            self.timestamp = None

    @property
    def es_critico(self) -> bool:
        """True si el nivel es WARN o ERROR."""
        return self.nivel in ("WARN", "ERROR")

    @property
    def ips_sospechosas(self) -> list:
        """IPs del mensaje que aparecen en la lista negra."""
        return [ip for ip in self.ips if ip in IPS_SOSPECHOSAS]

    def __repr__(self) -> str:
        return f"[{self.fecha} {self.hora}] {self.nivel:<5} [{self.modulo}] {self.mensaje}"

def parsear_log(ruta: str) -> tuple[list[EventoLog], int]:
    """
    Lee el archivo de log linea a linea y extrae eventos estructurados.

    Parametros
    ----------
    ruta : str   Ruta al archivo de log.

    return
    -------
    tuple[list[EventoLog], int]
        (lista de eventos validos, numero de lineas no parseadas)

    Nota forense
    ------------
    Convertir texto libre a estructura indexada es el primer paso de
    cualquier analisis. Permite busquedas eficientes, ordenacion
    cronologica y cruce con otras fuentes de evidencia.
    """
    eventos      = []
    no_parseadas = 0

    with open(ruta, "r", encoding="utf-8-sig", errors="replace") as f:
        for num_linea, linea in enumerate(f, start=1):
            linea = linea.rstrip()
            if not linea or linea.startswith("#"):
                continue

            m = PATRON_LOG.match(linea)
            if m:
                eventos.append(EventoLog(
                    m.group("fecha"), m.group("hora"),
                    m.group("nivel"), m.group("modulo"),
                    m.group("mensaje"), linea
                ))
            else:
                no_parseadas += 1
                # Mostrar las primeras 3 lineas no parseadas para diagnostico
                if no_parseadas <= 3:
                    print(f"  [!] Linea {num_linea} no coincide con el patron: {linea[:80]}")

    return eventos, no_parseadas

def analizar_eventos(eventos: list[EventoLog]) -> dict:
    """
    Construye estadisticas forenses a partir de la lista de eventos.

    Parametros
    ----------
    eventos : list[EventoLog]

    return
    -------
    dict con conteos, listas de criticos y alertas de IPs sospechosas.
    """
    conteo_nivel  = Counter(e.nivel  for e in eventos)
    conteo_modulo = Counter(e.modulo for e in eventos)

    conteo_ip = Counter()
    for e in eventos:
        for ip in e.ips:
            conteo_ip[ip] += 1

    criticos = [e for e in eventos if e.es_critico]

    sospechosas_activas: dict[str, list[EventoLog]] = defaultdict(list)
    for e in eventos:
        for ip in e.ips_sospechosas:
            sospechosas_activas[ip].append(e)

    exfiltracion = [
        e for e in eventos
        if e.modulo == "usb" and e.nivel == "WARN"
    ]

    return {
        "total_eventos":       len(eventos),
        "conteo_nivel":        conteo_nivel,
        "conteo_modulo":       conteo_modulo,
        "conteo_ip":           conteo_ip,
        "criticos":            criticos,
        "sospechosas_activas": dict(sospechosas_activas),
        "alertas_usb":         exfiltracion,
    }

def mostrar_resumen(analisis: dict, top_n: int = 10) -> None:
    """Imprime el informe de analisis forense por pantalla."""

    print(f"\n{'='*65}")
    print("  RESUMEN DEL ANALISIS FORENSE DE LOG")
    print(f"{'='*65}")
    print(f"  Total de eventos procesados: {analisis['total_eventos']}")

    print(f"\n  Distribucion por nivel:")
    for nivel, count in analisis["conteo_nivel"].most_common():
        print(f"    {nivel:<10} {count:>4} eventos")

    print(f"\n  Distribucion por modulo:")
    for modulo, count in analisis["conteo_modulo"].most_common():
        print(f"    [{modulo:<8}] {count:>4} eventos")

    if analisis["conteo_ip"]:
        print(f"\n  Top {top_n} IPs detectadas en mensajes:")
        for ip, count in analisis["conteo_ip"].most_common(top_n):
            flag   = " [SOSPECHOSA]" if ip in IPS_SOSPECHOSAS else ""
            motivo = f" - {IPS_SOSPECHOSAS[ip]}" if ip in IPS_SOSPECHOSAS else ""
            print(f"    {ip:<20} {count:>3} apariciones{flag}{motivo}")

    if analisis["criticos"]:
        print(f"\n  [!] Eventos criticos (WARN / ERROR): {len(analisis['criticos'])}")
        for e in analisis["criticos"]:
            print(f"    {e}")

    if analisis["sospechosas_activas"]:
        print(f"\n  [ALERTA] ACTIVIDAD DESDE IPs EN LISTA NEGRA:")
        for ip, evts in analisis["sospechosas_activas"].items():
            modulos_uniq = sorted({e.modulo for e in evts})
            print(f"    {ip:<20} ({IPS_SOSPECHOSAS[ip]})")
            print(f"      Eventos: {len(evts)} | Modulos: {', '.join(modulos_uniq)}")
            evts_ts = sorted([e for e in evts if e.timestamp], key=lambda e: e.timestamp)
            if evts_ts:
                print(f"      Primera actividad: {evts_ts[0].timestamp}")
                print(f"      Ultima actividad : {evts_ts[-1].timestamp}")

    if analisis["alertas_usb"]:
        print(f"\n  [ALERTA] DISPOSITIVOS USB DETECTADOS: {len(analisis['alertas_usb'])}")
        for e in analisis["alertas_usb"]:
            print(f"    {e}")

    print(f"\n{'='*65}")


def filtrar_y_mostrar(eventos: list[EventoLog],
                      filtro_ip: str = None,
                      filtro_nivel: str = None) -> None:
    """Muestra eventos filtrados por IP o nivel."""
    filtrados = eventos

    if filtro_ip:
        filtrados = [e for e in filtrados if filtro_ip in e.ips]
        print(f"\n  Eventos con IP {filtro_ip}: {len(filtrados)} encontrados\n")

    if filtro_nivel:
        filtrados = [e for e in filtrados if e.nivel == filtro_nivel.upper()]
        print(f"\n  Eventos de nivel '{filtro_nivel.upper()}': {len(filtrados)} encontrados\n")

    for e in filtrados:
        alerta = "  [!]" if e.ips_sospechosas else ""
        print(f"  {e}{alerta}")


def exportar_csv(eventos: list[EventoLog], archivo: str = "log_analisis.csv") -> None:
    """Exporta todos los eventos parseados a un CSV."""
    campos = ["fecha", "hora", "nivel", "modulo", "mensaje",
              "ips_detectadas", "es_critico", "ips_sospechosas", "linea_raw"]

    with open(archivo, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=campos)
        escritor.writeheader()
        for e in eventos:
            escritor.writerow({
                "fecha":           e.fecha,
                "hora":            e.hora,
                "nivel":           e.nivel,
                "modulo":          e.modulo,
                "mensaje":         e.mensaje,
                "ips_detectadas":  "|".join(e.ips),
                "es_critico":      e.es_critico,
                "ips_sospechosas": "|".join(e.ips_sospechosas),
                "linea_raw":       e.linea_raw,
            })

    print(f"\n[+] Eventos exportados a: {archivo}")



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    ruta_log = sys.argv[1]
    args     = sys.argv[2:]

    if not os.path.isfile(ruta_log):
        print(f"\n[ERROR] No se encuentra el archivo: {ruta_log}\n")
        sys.exit(1)

    top_n        = 10
    filtro_ip    = None
    filtro_nivel = None
    exportar     = "--csv"     in args
    solo_resumen = "--resumen" in args

    if "--top" in args:
        idx = args.index("--top")
        try:
            top_n = int(args[idx + 1])
        except (IndexError, ValueError):
            top_n = 10

    if "--nivel" in args:
        idx = args.index("--nivel")
        try:
            filtro_nivel = args[idx + 1]
        except IndexError:
            pass

    if "--ip" in args:
        idx = args.index("--ip")
        try:
            filtro_ip = args[idx + 1]
        except IndexError:
            pass

    print(f"\n[*] Analizando log: {ruta_log}")
    eventos, no_parseadas = parsear_log(ruta_log)

    print(f"[+] Eventos parseados: {len(eventos)}")
    if no_parseadas > 0:
        print(f"[!] Lineas no parseadas: {no_parseadas} (ver arriba para detalles)")

    analisis = analizar_eventos(eventos)

    mostrar_resumen(analisis, top_n=top_n)

    if not solo_resumen and (filtro_ip or filtro_nivel):
        filtrar_y_mostrar(eventos, filtro_ip=filtro_ip, filtro_nivel=filtro_nivel)
    elif not solo_resumen and not filtro_ip and not filtro_nivel:
        print("\n  Todos los eventos (usa --nivel o --ip para filtrar):")
        for e in eventos:
            alerta = "  [!]" if e.ips_sospechosas else ""
            print(f"  {e}{alerta}")

    if exportar:
        exportar_csv(eventos)
