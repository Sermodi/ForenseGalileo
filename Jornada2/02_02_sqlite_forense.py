#!/usr/bin/env python3
"""
sqlite_forense.py
=================
EJERCICIO 2 — Jornada 2: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Analiza bases de datos SQLite como artefacto forense. Cubre:
  - Extracción del esquema (tablas, columnas, índices)
  - Consulta de registros con filtros temporales
  - Recuperación de registros borrados (páginas libres)
  - Exportación de resultados a CSV con hash de integridad

Uso
---
    python sqlite_forense.py <evidencia.db>
    python sqlite_forense.py --generar-demo   # Crea BD de demostración

Dependencias
------------
    Sólo librerías estándar (sqlite3, csv, hashlib, struct)

Autor   : Sergio M.
Versión : 1.0
Fecha   : 2026-04-10
"""

import sqlite3
import sys
import csv
import hashlib
import struct
from pathlib import Path
from datetime import datetime


def generar_demo_db(ruta: str = "evidencia_demo.db") -> None:
    """Crea una BD SQLite simulada con mensajes, contactos y actividad."""
    con = sqlite3.connect(ruta)
    cur = con.cursor()

    # Tabla de mensajes (similar a bases de datos de WhatsApp / Signal)
    cur.executescript("""
        DROP TABLE IF EXISTS mensajes;
        DROP TABLE IF EXISTS contactos;
        DROP TABLE IF EXISTS actividad_app;

        CREATE TABLE contactos (
            id       INTEGER PRIMARY KEY,
            nombre   TEXT NOT NULL,
            telefono TEXT,
            email    TEXT
        );

        CREATE TABLE mensajes (
            id          INTEGER PRIMARY KEY,
            remitente   INTEGER REFERENCES contactos(id),
            destinatario INTEGER REFERENCES contactos(id),
            cuerpo      TEXT,
            timestamp   INTEGER,  -- Unix epoch
            leido       INTEGER DEFAULT 0,
            borrado     INTEGER DEFAULT 0
        );

        CREATE TABLE actividad_app (
            id        INTEGER PRIMARY KEY,
            evento    TEXT,
            timestamp INTEGER,
            detalle   TEXT
        );
    """)

    # Datos de demostración
    contactos = [
        (1, "Juan Pérez",    "+34600111222", "jperez@empresa.com"),
        (2, "María García",  "+34600333444", "mgarcia@empresa.com"),
        (3, "Número Oculto", "+447890123456", None),
    ]
    cur.executemany("INSERT INTO contactos VALUES (?,?,?,?)", contactos)

    # Timestamps en Unix epoch (segundos desde 1970-01-01)
    mensajes = [
        (1,  1, 2, "Hola María, ¿puedes enviarme los contratos de exportación?", 1742030400, 1, 0),
        (2,  2, 1, "Claro, te los mando por Drive.",                              1742030600, 1, 0),
        (3,  1, 3, "Confirma recepción del paquete.",                             1742031000, 0, 0),
        (4,  3, 1, "Recibido. Procedo según lo acordado.",                        1742031120, 0, 0),
        (5,  1, 2, "Borra este hilo cuando puedas.",                              1742031200, 1, 1),  # borrado
        (6,  2, 1, "De acuerdo.",                                                 1742031300, 1, 1),  # borrado
        (7,  1, 3, "Necesito factura proforma para 50 unidades.",                 1742118000, 0, 0),
    ]
    cur.executemany("INSERT INTO mensajes VALUES (?,?,?,?,?,?,?)", mensajes)

    actividad = [
        (1, "APP_INICIO",   1742030300, "Versión 2.14.5"),
        (2, "PANTALLA",     1742030320, "Contactos"),
        (3, "PANTALLA",     1742031180, "Chat:JuanPérez"),
        (4, "CAPTURA",      1742031185, "screenshot_001.png"),
        (5, "APP_FIN",      1742031400, None),
    ]
    cur.executemany("INSERT INTO actividad_app VALUES (?,?,?,?)", actividad)

    con.commit()
    con.close()

    sha256 = hashlib.sha256(Path(ruta).read_bytes()).hexdigest()
    print(f"[OK] BD de demostración creada: {ruta}")
    print(f"     SHA-256: {sha256}")
    print(f"\nSiguiente paso:")
    print(f"  python sqlite_forense.py {ruta}")



def epoch_a_fecha(ts) -> str:
    """Convierte Unix epoch a cadena legible. Maneja valores None o vacíos."""
    if ts is None:
        return "N/A"
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError):
        return str(ts)


def extraer_esquema(cur) -> dict:
    """Extrae el esquema completo de la base de datos."""
    esquema = {}
    cur.execute("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")
    for nombre, tipo, sql in cur.fetchall():
        cur.execute(f"SELECT COUNT(*) FROM '{nombre}'")
        total = cur.fetchone()[0]
        esquema[nombre] = {"tipo": tipo, "sql": sql, "filas": total}
    return esquema


def analizar_mensajes(cur) -> list:
    """Extrae todos los mensajes, incluidos los marcados como borrados."""
    cur.execute("""
        SELECT m.id,
               c_rem.nombre  AS remitente,
               c_des.nombre  AS destinatario,
               m.cuerpo,
               m.timestamp,
               m.leido,
               m.borrado
        FROM mensajes m
        LEFT JOIN contactos c_rem ON m.remitente    = c_rem.id
        LEFT JOIN contactos c_des ON m.destinatario = c_des.id
        ORDER BY m.timestamp
    """)
    return cur.fetchall()


def analizar_sqlite(ruta_db: str) -> None:
    """Punto de entrada del análisis forense sobre un fichero SQLite."""

    ruta = Path(ruta_db)
    if not ruta.exists():
        print(f"[ERROR] Fichero no encontrado: {ruta}")
        sys.exit(1)

    # 1. Integridad: hash antes de tocar nada
    datos_raw = ruta.read_bytes()
    sha256 = hashlib.sha256(datos_raw).hexdigest()
    md5    = hashlib.md5(datos_raw).hexdigest()

    print("\n" + "="*65)
    print("  ANÁLISIS FORENSE — BASE DE DATOS SQLITE")
    print("="*65)
    print(f"\n  Fichero   : {ruta.name}")
    print(f"  Tamaño    : {ruta.stat().st_size:,} bytes")
    print(f"  MD5       : {md5}")
    print(f"  SHA-256   : {sha256[:32]}...")

    # 2. Cabecera SQLite (primeros 100 bytes son la cabecera estándar)
    # Ref: https://www.sqlite.org/fileformat.html
    if datos_raw[:16] == b"SQLite format 3\x00":
        page_size = struct.unpack(">H", datos_raw[16:18])[0]
        # page_size=1 significa 65536
        if page_size == 1:
            page_size = 65536
        n_pages = struct.unpack(">I", datos_raw[28:32])[0]
        version_write = struct.unpack(">I", datos_raw[60:64])[0]
        print(f"\n  [+] Firma SQLite válida")
        print(f"  Tamaño de página : {page_size} bytes")
        print(f"  Páginas totales  : {n_pages}")
        print(f"  Versión escritura: {version_write}")
    else:
        print("\n  [!] No se detectó firma SQLite estándar — puede estar cifrada o corrupta")

    # 3. Conexión y análisis lógico
    con = sqlite3.connect(ruta_db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    esquema = extraer_esquema(cur)
    print(f"\n  Tablas encontradas: {len(esquema)}")
    for nombre, info in esquema.items():
        print(f"    [{info['tipo'].upper()}] {nombre:<25} ({info['filas']} registros)")

    # 4. Análisis de mensajes
    if "mensajes" in esquema:
        print("\n" + "-"*65)
        print("  MENSAJES (incluye registros borrados)")
        print("-"*65)

        filas = analizar_mensajes(cur)
        borrados = [f for f in filas if f[6] == 1]
        activos  = [f for f in filas if f[6] == 0]

        print(f"\n  Total: {len(filas)} | Activos: {len(activos)} | Borrados: {len(borrados)}")

        for f in filas:
            estado = "🗑️  BORRADO" if f[6] == 1 else "✉️  Activo "
            ts_str = epoch_a_fecha(f[4])
            print(f"\n  {estado} | ID:{f[0]}")
            print(f"    De: {f[1]} → Para: {f[2]}")
            print(f"    Texto: {f[3]}")
            print(f"    Fecha: {ts_str}")

        csv_path = "mensajes_extraidos.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(["id","remitente","destinatario","cuerpo","timestamp_utc","leido","borrado"])
            for f in filas:
                writer.writerow([f[0], f[1], f[2], f[3], epoch_a_fecha(f[4]), f[5], f[6]])
        print(f"\n  [+] Mensajes exportados → {csv_path}")

    # 5. Actividad de aplicación
    if "actividad_app" in esquema:
        print("\n" + "-"*65)
        print("  ACTIVIDAD DE LA APLICACIÓN")
        print("-"*65)
        cur.execute("SELECT id, evento, timestamp, detalle FROM actividad_app ORDER BY timestamp")
        for fila in cur.fetchall():
            ts_str = epoch_a_fecha(fila[2])
            detalle = fila[3] if fila[3] else ""
            print(f"  {ts_str}  [{fila[1]:<15}] {detalle}")

    con.close()
    print("\n" + "="*65)
    print("  Análisis completado.")
    print("="*65)


def main():
    if "--generar-demo" in sys.argv:
        generar_demo_db()
        return

    if len(sys.argv) < 2:
        print("Uso: python sqlite_forense.py <evidencia.db>")
        print("     python sqlite_forense.py --generar-demo")
        sys.exit(1)

    analizar_sqlite(sys.argv[1])


if __name__ == "__main__":
    main()
