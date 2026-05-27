#!/usr/bin/env python3
"""
inventario_forense.py
=====================
EJERCICIO 1 — Jornada 1: Informatica Forense con Python
Formación GalileoForense

Descripcion
-----------
Genera un inventario completo de todos los archivos en un directorio
(simulando el contenido de un USB sospechoso) y exporta los resultados
a un archivo CSV listo para incluir en el informe pericial.

Uso
---
    python inventario_forense.py <directorio> [extension_filtro]

    directorio       : Ruta al directorio a inventariar (ej: ./evidencias_usb)
    extension_filtro : (Opcional) Filtrar por extension, ej: .jpg  .docx

Ejemplos
--------
    python inventario_forense.py ./evidencias_usb
    python inventario_forense.py ./evidencias_usb .jpg

Salida
------
    inventario.csv  — Archivo CSV con todos los metadatos encontrados.
    Resumen por pantalla al finalizar.

Autor   : SergioM.
Version : 1.0
Fecha   : 2026-04-01
"""

import os
import sys
import csv
import datetime
import mimetypes

CAMPOS_CSV = [
    "nombre",
    "extension",
    "mime_type",
    "tamanio_bytes",
    "tamanio_legible",
    "fecha_modificacion",
    "fecha_creacion",
    "ruta_relativa",
    "ruta_absoluta",
]

ARCHIVO_SALIDA = "inventario.csv"

def tamanio_legible(bytes_: int) -> str:
    """
    Convierte un tamaño en bytes a una cadena legible (KB, MB, GB).

    Parametros
    ----------
    bytes_ : int
        Tamaño en bytes.

    return
    -------
    str
        Cadena con el tamaño formateado, ej: '1.23 MB'.
    """
    for unidad in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_ < 1024:
            return f"{bytes_:.2f} {unidad}"
        bytes_ /= 1024
    return f"{bytes_:.2f} PB"


def timestamp_a_fecha(timestamp: float) -> str:
    """
    Convierte un timestamp UNIX a cadena de fecha/hora legible.

    Parametros
    ----------
    timestamp : float
        Timestamp UNIX (segundos desde 1970-01-01).

    return
    -------
    str
        Fecha formateada como 'YYYY-MM-DD HH:MM:SS'.

    El timestamp registrado depende del sistema de archivos y del SO.
    En NTFS se almacenan hasta 100 ns de precision. En FAT32 solo 2 s.
    Siempre documentar el SO y el sistema de archivos origen.
    """
    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def detectar_mime(ruta: str) -> str:
    """
    Detecta el tipo MIME real de un archivo segun su extension.

    Parametros
    ----------
    ruta : str
        Ruta completa al archivo.

    return
    -------
    str
        Tipo MIME, ej: 'image/jpeg'. Devuelve 'desconocido' si no se detecta.

    Este metodo usa la extension para inferir el MIME. Para una deteccion
    mas robusta (basada en magic bytes) usar la libreria 'python-magic'.
    """
    mime, _ = mimetypes.guess_type(ruta)
    return mime if mime else "desconocido"

def inventariar_directorio(directorio: str, filtro_ext: str = None) -> list[dict]:
    """
    Recorre recursivamente un directorio y extrae metadatos de cada archivo.

    Parametros
    ----------
    directorio : str
        Ruta al directorio raiz a analizar.
    filtro_ext : str, opcional
        Si se indica, solo se procesan archivos con esa extensión (ej: '.jpg').

    return
    -------
    list[dict]
        Lista de diccionarios con los metadatos de cada archivo encontrado.

    Se usa os.walk() para recorrer todo el arbol de directorios con una
    sola llamada, independientemente de la profundidad. Los archivos
    ocultos (que comienzan por '.') tambien se incluyen.
    """
    registros = []
    errores = []

    for raiz, _dirs, archivos in os.walk(directorio):
        for nombre_archivo in archivos:
            ruta_abs = os.path.join(raiz, nombre_archivo)

            # Aplicar filtro de extension si se indico
            _, extension = os.path.splitext(nombre_archivo)
            if filtro_ext and extension.lower() != filtro_ext.lower():
                continue

            try:
                stat = os.stat(ruta_abs)
                ruta_relativa = os.path.relpath(ruta_abs, directorio)

                registro = {
                    "nombre":           nombre_archivo,
                    "extension":        extension.lower() if extension else "(sin ext)",
                    "mime_type":        detectar_mime(ruta_abs),
                    "tamanio_bytes":    stat.st_size,
                    "tamanio_legible":  tamanio_legible(stat.st_size),
                    "fecha_modificacion": timestamp_a_fecha(stat.st_mtime),
                    "fecha_creacion":   timestamp_a_fecha(stat.st_ctime),
                    "ruta_relativa":    ruta_relativa,
                    "ruta_absoluta":    ruta_abs,
                }
                registros.append(registro)

            except (PermissionError, FileNotFoundError, OSError) as e:
                # Registrar errores sin interrumpir el analisis
                errores.append(f"  [ERROR] {ruta_abs}: {e}")

    if errores:
        print("\n[!] Archivos no accesibles:")
        for err in errores:
            print(err)

    return registros


def guardar_csv(registros: list[dict], ruta_salida: str) -> None:
    """
    Exporta los registros de inventario a un archivo CSV.

    Parametros
    ----------
    registros   : list[dict]
        Lista de diccionarios con los metadatos.
    ruta_salida : str
        Ruta del archivo CSV a crear.
    """
    with open(ruta_salida, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=CAMPOS_CSV, delimiter=";")
        escritor.writeheader()
        escritor.writerows(registros)


def mostrar_resumen(registros: list[dict], directorio: str, filtro_ext: str = None) -> None:
    """
    Muestra por pantalla un resumen estadistico del inventario.

    Parametros
    ----------
    registros  : list[dict]
        Lista de registros obtenidos del inventario.
    directorio : str
        Directorio analizado.
    filtro_ext : str, opcional
        Filtro de extension aplicado.
    """
    if not registros:
        print("\n[!] No se encontraron archivos.")
        return

    total_bytes = sum(r["tamanio_bytes"] for r in registros)

    # Agrupar por extensión
    conteo_ext: dict[str, int] = {}
    for r in registros:
        ext = r["extension"]
        conteo_ext[ext] = conteo_ext.get(ext, 0) + 1

    print("\n" + "=" * 60)
    print("  RESUMEN DEL INVENTARIO FORENSE")
    print("=" * 60)
    print(f"  Directorio analizado : {os.path.abspath(directorio)}")
    if filtro_ext:
        print(f"  Filtro de extension  : {filtro_ext}")
    print(f"  Total de archivos    : {len(registros)}")
    print(f"  Tamano total         : {tamanio_legible(total_bytes)}")
    print(f"  Archivo de salida    : {ARCHIVO_SALIDA}")
    print()
    print("  Distribucion por extension:")
    for ext, count in sorted(conteo_ext.items(), key=lambda x: -x[1]):
        print(f"    {ext:<15} {count:>4} archivo(s)")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n[ERROR] Debes indicar un directorio.\n")
        print(f"  Uso: python {os.path.basename(__file__)} <directorio> [extension]")
        sys.exit(1)

    ruta_directorio = sys.argv[1]
    extension_filtro = sys.argv[2] if len(sys.argv) >= 3 else None

    if not os.path.isdir(ruta_directorio):
        print(f"\n[ERROR] El directorio '{ruta_directorio}' no existe.\n")
        sys.exit(1)

    print(f"\n[*] Iniciando inventario forense en: {ruta_directorio}")
    if extension_filtro:
        print(f"[*] Filtro activo: solo archivos '{extension_filtro}'")

    registros = inventariar_directorio(ruta_directorio, extension_filtro)

    guardar_csv(registros, ARCHIVO_SALIDA)
    print(f"[+] Inventario exportado a: {ARCHIVO_SALIDA}")

    mostrar_resumen(registros, ruta_directorio, extension_filtro)
