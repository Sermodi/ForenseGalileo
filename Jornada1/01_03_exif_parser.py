#!/usr/bin/env python3
"""
exif_parser.py
==============
EJERCICIO 3 — Jornada 1: Informatica Forense con Python
Formacion GalileoForense

Descripcion
-----------
Extrae y muestra todos los metadatos EXIF de imagenes JPEG/TIFF,
incluyendo coordenadas GPS con conversion a grados decimales y
enlace directo a Google Maps. Exporta los resultados a CSV.

Uso
---
    python exif_parser.py <imagen_o_directorio> [--csv]

    imagen_o_directorio : Ruta a una imagen o a un directorio con imagenes.
    --csv               : (Opcional) Exportar resultados a exif_resultados.csv

Ejemplos
--------
    python exif_parser.py ./evidencias_usb/foto.jpg
    python exif_parser.py ./evidencias_usb/
    python exif_parser.py ./evidencias_usb/ --csv

Dependencias
------------
    pip install Pillow

Dataset de prueba con GPS real:
    https://github.com/ianare/exif-samples
    (Descargar y colocar en ./evidencias_usb/imagenes/)

Autor   : SergioM.
Version : 1.0
Fecha   : 2026-04-02
"""

import os
import sys
import csv
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    print("\n[ERROR] Pillow no esta instalado.")
    print("        Instalalo con: pip install Pillow\n")
    sys.exit(1)

EXTENSIONES_IMAGEN = {".jpg", ".jpeg", ".tiff", ".tif", ".png"}

def extraer_exif_raw(ruta: str) -> dict:
    """
    Abre una imagen y devuelve todos sus metadatos EXIF en bruto.

    Parametros
    ----------
    ruta : str
        Ruta completa a la imagen JPEG o TIFF.

    return
    -------
    dict
        Diccionario {nombre_campo: valor} con todos los tags EXIF
        disponibles en la imagen. Devuelve {} si no hay EXIF.

    Nota forense
    ------------
    _getexif() devuelve los IDs numericos de los tags. TAGS es un
    diccionario de PIL que mapea esos IDs a nombres legibles como
    'Make', 'DateTime', 'GPSInfo', etc.

    Atencion: algunas camaras usan tags propietarios no cubiertos
    por el estandar EXIF 2.3. PIL los lista igualmente como desconocidos.
    """
    try:
        img  = Image.open(ruta)
        data = img._getexif()
        if not data:
            return {}
        # Traducir IDs numericos a nombres legibles
        return {TAGS.get(tag_id, f"Tag_{tag_id}"): valor
                for tag_id, valor in data.items()}
    except Exception as e:
        print(f"  [ERROR] No se pudo leer EXIF de {os.path.basename(ruta)}: {e}")
        return {}

def coordenada_a_decimal(coords, ref: str) -> float:
    """
    Convierte coordenadas GPS del formato DMS (grados/minutos/segundos)
    al formato decimal estandar (WGS-84).

    Parametros
    ----------
    coords : tuple
        Tupla con (grados, minutos, segundos). Cada valor puede ser
        un entero, float o fraccion rational (IFDRational de PIL).
    ref    : str
        Referencia cardinal: 'N', 'S' (latitud) o 'E', 'W' (longitud).
        'S' y 'W' producen valores negativos.

    return
    -------
    float
        Coordenada en grados decimales. Ej: 40.4168 (Madrid latitud).

    Ejemplo de conversion
    ---------------------
    DMS: 40° 25' 0.48"  N  →  40 + 25/60 + 0.48/3600 = 40.41680
    DMS: 03° 42' 13.68" W  →  -(3 + 42/60 + 13.68/3600) = -3.70380
    """
    grados   = float(coords[0])
    minutos  = float(coords[1])
    segundos = float(coords[2])

    decimal = grados + (minutos / 60.0) + (segundos / 3600.0)

    # Sur y Oeste son negativos en el sistema de coordenadas WGS-84
    if ref in ("S", "W"):
        decimal = -decimal

    return round(decimal, 6)

def extraer_gps(exif: dict) -> dict | None:
    """
    Extrae y convierte los datos GPS del bloque EXIF a coordenadas decimales.

    Parametros
    ----------
    exif : dict
        Diccionario EXIF devuelto por extraer_exif_raw().

    return
    -------
    dict o None
        Diccionario con 'latitud', 'longitud', 'altitud', 'velocidad',
        'maps_url' si hay datos GPS. None si no hay informacion GPS.

    Nota forense
    ------------
    Las coordenadas GPS en una fotografía pueden situar a una persona
    en un lugar concreto en un momento concreto. Es una de las evidencias
    mas potentes que puede contener un archivo de imagen digital.

    IMPORTANTE: las coordenadas GPS reflejan la posicion del dispositivo
    en el momento de captura, segun su reloj y GPS internos. Documentar
    siempre si el dispositivo tenia el GPS activo y si el reloj era correcto.
    """
    gps_raw = exif.get("GPSInfo")
    if not gps_raw:
        return None

    # Traducir IDs numericos de GPS a nombres legibles
    gps = {GPSTAGS.get(tag_id, f"GPS_{tag_id}"): valor
           for tag_id, valor in gps_raw.items()}

    resultado = {}

    # Latitud
    if "GPSLatitude" in gps and "GPSLatitudeRef" in gps:
        resultado["latitud"] = coordenada_a_decimal(
            gps["GPSLatitude"], gps["GPSLatitudeRef"]
        )

    # Longitud
    if "GPSLongitude" in gps and "GPSLongitudeRef" in gps:
        resultado["longitud"] = coordenada_a_decimal(
            gps["GPSLongitude"], gps["GPSLongitudeRef"]
        )

    # Altitud (metros sobre el nivel del mar)
    if "GPSAltitude" in gps:
        resultado["altitud_m"] = round(float(gps["GPSAltitude"]), 2)
        ref_alt = gps.get("GPSAltitudeRef", 0)
        if ref_alt == 1:
            resultado["altitud_m"] = -resultado["altitud_m"]

    # Velocidad
    if "GPSSpeed" in gps:
        resultado["velocidad_kmh"] = round(float(gps["GPSSpeed"]), 2)

    # Timestamp GPS (puede diferir del reloj del dispositivo)
    if "GPSTimeStamp" in gps:
        ts = gps["GPSTimeStamp"]
        resultado["gps_hora_utc"] = f"{int(ts[0]):02d}:{int(ts[1]):02d}:{int(ts[2]):02d}"

    # Generar URL de Google Maps si tenemos latitud y longitud
    if "latitud" in resultado and "longitud" in resultado:
        lat = resultado["latitud"]
        lon = resultado["longitud"]
        resultado["maps_url"] = f"https://maps.google.com/?q={lat},{lon}"

    return resultado if resultado else None

def analizar_imagen(ruta: str, verbose: bool = True) -> dict:
    """
    Analiza una imagen y devuelve un resumen de sus metadatos forenses.

    Parametros
    ----------
    ruta    : str
        Ruta a la imagen.
    verbose : bool
        Si True, imprime los resultados por pantalla.

    return
    -------
    dict
        Diccionario con los metadatos relevantes extraidos.
    """
    if verbose:
        print(f"\n{'='*65}")
        print(f"  IMAGEN : {os.path.basename(ruta)}")
        print(f"  RUTA   : {os.path.abspath(ruta)}")
        print(f"{'='*65}")

    exif = extraer_exif_raw(ruta)

    if not exif:
        if verbose:
            print("  [!] Esta imagen no contiene metadatos EXIF.")
        return {"archivo": ruta, "exif": False}

    # Campos relevantes para forense
    campos_interes = [
        ("Make",             "Fabricante del dispositivo"),
        ("Model",            "Modelo del dispositivo"),
        ("Software",         "Software de edicion"),
        ("DateTime",         "Fecha de captura (reloj dispositivo)"),
        ("DateTimeOriginal", "Fecha original (sin edicion)"),
        ("DateTimeDigitized","Fecha de digitalizacion"),
        ("ImageWidth",       "Ancho (px)"),
        ("ImageLength",      "Alto (px)"),
        ("ExifImageWidth",   "Ancho EXIF (px)"),
        ("ExifImageHeight",  "Alto EXIF (px)"),
        ("FNumber",          "Apertura"),
        ("ISOSpeedRatings",  "ISO"),
        ("ExposureTime",     "Tiempo de exposicion"),
        ("FocalLength",      "Focal (mm)"),
        ("Flash",            "Flash"),
        ("Orientation",      "Orientacion"),
        ("SerialNumber",     "Numero de serie"),
        ("LensModel",        "Modelo de objetivo"),
    ]

    resumen = {"archivo": os.path.basename(ruta), "exif": True}

    if verbose:
        print("\n  --- METADATOS GENERALES ---")

    for campo, descripcion in campos_interes:
        valor = exif.get(campo)
        if valor is not None:
            valor_str = str(valor)
            resumen[campo] = valor_str
            if verbose:
                print(f"  {descripcion:<35} {valor_str}")

    # Datos GPS
    gps = extraer_gps(exif)
    if gps:
        if verbose:
            print("\n  --- DATOS GPS ---")
        for clave, valor in gps.items():
            resumen[f"GPS_{clave}"] = str(valor)
            if verbose:
                print(f"  {clave:<35} {valor}")
        if "maps_url" in gps and verbose:
            print(f"\n  [!] Localizar en mapa: {gps['maps_url']}")
    else:
        if verbose:
            print("\n  [i] No hay datos GPS en esta imagen.")

    return resumen

def analizar_directorio(directorio: str, exportar_csv: bool = False) -> list[dict]:
    """
    Analiza todas las imagenes de un directorio recursivamente.

    Parametros
    ----------
    directorio  : str
        Ruta al directorio con imagenes.
    exportar_csv : bool
        Si True, exporta los resultados a exif_resultados.csv.

    return
    -------
    list[dict]
        Lista de resultados por imagen.
    """
    resultados = []
    imagenes_encontradas = 0

    for raiz, _dirs, archivos in os.walk(directorio):
        for nombre in archivos:
            _, ext = os.path.splitext(nombre)
            if ext.lower() in EXTENSIONES_IMAGEN:
                ruta_abs = os.path.join(raiz, nombre)
                imagenes_encontradas += 1
                resultado = analizar_imagen(ruta_abs, verbose=True)
                resultados.append(resultado)

    print(f"\n[+] Total de imagenes analizadas: {imagenes_encontradas}")

    if exportar_csv and resultados:
        _exportar_csv(resultados)

    return resultados

def _exportar_csv(resultados: list[dict], archivo: str = "exif_resultados.csv") -> None:
    """
    Exporta los resultados EXIF a un CSV apto para el informe pericial.

    Parametros
    ----------
    resultados : list[dict]
        Lista de diccionarios con los metadatos por imagen.
    archivo    : str
        Nombre del archivo CSV de salida.
    """
    todas_las_claves = set()
    for r in resultados:
        todas_las_claves.update(r.keys())
    campos = sorted(todas_las_claves)

    with open(archivo, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=campos, extrasaction="ignore")
        escritor.writeheader()
        escritor.writerows(resultados)

    print(f"[+] Resultados EXIF exportados a: {archivo}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    ruta       = sys.argv[1]
    exportar   = "--csv" in sys.argv

    if os.path.isfile(ruta):
        _, ext = os.path.splitext(ruta)
        if ext.lower() not in EXTENSIONES_IMAGEN:
            print(f"\n[ERROR] Formato no soportado: {ext}")
            print(f"        Formatos validos: {', '.join(EXTENSIONES_IMAGEN)}\n")
            sys.exit(1)

        resultado = analizar_imagen(ruta, verbose=True)

        if exportar:
            _exportar_csv([resultado])

    elif os.path.isdir(ruta):
        print(f"\n[*] Analizando directorio: {ruta}\n")
        analizar_directorio(ruta, exportar_csv=exportar)

    else:
        print(f"\n[ERROR] Ruta no valida: '{ruta}'\n")
        sys.exit(1)
