import sqlite3
import sys
import csv
import hashlib
import struct
from pathlib import Path
from datetime import datetime


ruta = "evidencia_demo.db"
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