#!/usr/bin/env python3
"""
hashing_evidencias.py
=====================
EJERCICIO 2 — Jornada 1: Informática Forense con Python
Formacion GalileoForense

Descripcion
-----------
Herramienta forense para calcular y verificar hashes criptograficos de
archivos y directorios completos. Garantiza la integridad de la evidencia
digital conforme a los estandares de cadena de custodia.

Modos de uso
------------
    # Calcular hash de un archivo
    python hashing_evidencias.py archivo <ruta_archivo> [algoritmo]

    # Calcular hashes de todos los archivos en un directorio
    python hashing_evidencias.py directorio <ruta_dir> [algoritmo]

    # Verificar integridad comparando con un hash conocido
    python hashing_evidencias.py verificar <ruta_archivo> <hash_esperado> [algoritmo]

    # Ampliar inventario_forense.py añadiendo hash SHA-256 al CSV
    python hashing_evidencias.py inventario <directorio>

Algoritmos disponibles: md5, sha1, sha256 (por defecto)

Ejemplos
--------
    python hashing_evidencias.py archivo ./evidencias_usb/foto.jpg
    python hashing_evidencias.py archivo ./evidencias_usb/foto.jpg md5
    python hashing_evidencias.py directorio ./evidencias_usb
    python hashing_evidencias.py verificar ./evidencias_usb/foto.jpg a3f5... sha256
    python hashing_evidencias.py inventario ./evidencias_usb

Autor   : SergioM.
Version : 1.0
Fecha   : 2026-04-01
"""

import os
import sys
import csv
import hashlib
import datetime

ALGORITMOS_VALIDOS = {"md5", "sha1", "sha256"}
ALGORITMO_POR_DEFECTO = "sha256"
TAMANIO_BLOQUE = 65536  # 64 KB — equilibrio entre velocidad y uso de memoria

def calcular_hash(ruta: str, algoritmo: str = "sha256") -> str:
    """
    Calcula el hash criptografico de un archivo leyendo en bloques.

    Leer el archivo en bloques (en lugar de cargarlo completo en memoria)
    permite procesar archivos de imagen forense de varios GB sin agotar
    la RAM del equipo de analisis.

    Parametros
    ----------
    ruta      : str
        Ruta completa al archivo.
    algoritmo : str
        Algoritmo hash: 'md5', 'sha1' o 'sha256'.

    return
    -------
    str
        Cadena hexadecimal del hash calculado.

    Raises
    ------
    ValueError
        Si el algoritmo indicado no esta soportado.
    FileNotFoundError
        Si el archivo no existe en la ruta indicada.

    Nota forense
    ------------
    MD5  — rapido, 128 bits. Colisiones conocidas: NO usar para firmar
           imagenes de disco. Valido solo para verificacion interna.
    SHA-1  — 160 bits. Obsoleto criptograficamente pero aun aceptado
             por algunos juzgados. Preferir SHA-256.
    SHA-256 — 256 bits. Estandar actual en laboratorios forenses.
              Es el recomendado para cadena de custodia.
    """
    if algoritmo not in ALGORITMOS_VALIDOS:
        raise ValueError(f"Algoritmo '{algoritmo}' no soportado. Usa: {ALGORITMOS_VALIDOS}")

    h = hashlib.new(algoritmo)

    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(TAMANIO_BLOQUE), b""):
            h.update(bloque)

    return h.hexdigest()


def calcular_hashes_multiples(ruta: str) -> dict[str, str]:
    """
    Calcula MD5, SHA-1 y SHA-256 de un archivo en un solo recorrido.

    Calcula los tres hashes en una única lectura del archivo para
    minimizar el acceso a disco — especialmente útil con evidencias
    en medios lentos (USB, discos cifrados, imágenes remotas).

    Parametros
    ----------
    ruta : str
        Ruta completa al archivo.

    return
    -------
    dict[str, str]
        Diccionario con claves 'md5', 'sha1', 'sha256' y sus valores hex.
    """
    hashers = {
        "md5":    hashlib.md5(),
        "sha1":   hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(TAMANIO_BLOQUE), b""):
            for h in hashers.values():
                h.update(bloque)

    return {nombre: h.hexdigest() for nombre, h in hashers.items()}

def verificar_integridad(ruta: str, hash_esperado: str, algoritmo: str = "sha256") -> bool:
    """
    Verifica que el hash actual de un archivo coincide con el hash de referencia.

    Este debería ser el procedimiento estandar para comprobar que una evidencia
    no ha sido modificada despues de su adquisicion forense.

    Parametros
    ----------
    ruta          : str
        Ruta al archivo a verificar.
    hash_esperado : str
        Hash de referencia registrado en el momento de la adquisicion.
    algoritmo     : str
        Algoritmo usado para calcular el hash original.

    return
    -------
    bool
        True si el hash coincide (evidencia integra), False si difiere.

    Nota forense
    ------------
    Si el hash NO coincide puede indicar:
      - Modificacion accidental (error de copia, fallo de hardware).
      - Modificacion deliberada (manipulacion de la evidencia).
      - Uso del algoritmo incorrecto para la verificacion.
    Cualquier discrepancia debe documentarse en un informe.
    """
    hash_actual = calcular_hash(ruta, algoritmo)
    return hash_actual.lower() == hash_esperado.lower().strip()

def inventario_con_hash(directorio: str, archivo_salida: str = "inventario_hash.csv") -> None:
    """
    Genera un inventario CSV de todos los archivos en un directorio
    incluyendo sus hashes MD5 y SHA-256.

    Esta funcion extiende inventario_forense.py incorporando las huellas
    digitales criptograficas de cada archivo — campo obligatorio en
    cualquier informe pericial de acuerdo a los estandares forenses.

    Parámetros
    ----------
    directorio    : str
        Ruta al directorio raiz a analizar.
    archivo_salida : str
        Nombre del CSV de salida.
    """
    campos = ["nombre", "extension", "tamanio_bytes", "fecha_modificacion",
              "md5", "sha256", "ruta_absoluta"]

    print(f"\n[*] Generando inventario con hashes en: {directorio}")
    print("[*] Este proceso puede tardar si hay archivos grandes...\n")

    registros = []
    total = 0

    with open(archivo_salida, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=campos)
        escritor.writeheader()

        for raiz, _dirs, archivos in os.walk(directorio):
            for nombre in archivos:
                ruta_abs = os.path.join(raiz, nombre)
                _, ext = os.path.splitext(nombre)

                try:
                    stat = os.stat(ruta_abs)
                    hashes = calcular_hashes_multiples(ruta_abs)
                    mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

                    registro = {
                        "nombre":              nombre,
                        "extension":           ext.lower() if ext else "(sin ext)",
                        "tamanio_bytes":       stat.st_size,
                        "fecha_modificacion":  mtime,
                        "md5":                 hashes["md5"],
                        "sha256":              hashes["sha256"],
                        "ruta_absoluta":       ruta_abs,
                    }
                    escritor.writerow(registro)
                    registros.append(registro)
                    total += 1
                    print(f"  [{total:>4}] {nombre[:50]:<50}  sha256: {hashes['sha256'][:16]}...")

                except (PermissionError, OSError) as e:
                    print(f"  [ERROR] {nombre}: {e}")

    print(f"\n[+] Inventario completado: {total} archivos procesados")
    print(f"[+] Guardado en: {archivo_salida}")

def _uso():
    print(__doc__)
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        _uso()

    modo = sys.argv[1].lower()

    if modo == "archivo":
        ruta = sys.argv[2]
        algoritmo = sys.argv[3] if len(sys.argv) >= 4 else ALGORITMO_POR_DEFECTO

        if not os.path.isfile(ruta):
            print(f"\n[ERROR] No se encuentra el archivo: {ruta}\n")
            sys.exit(1)

        print(f"\n[*] Calculando hashes de: {ruta}")
        hashes = calcular_hashes_multiples(ruta)
        stat = os.stat(ruta)

        print(f"\n{'='*60}")
        print(f"  Archivo  : {os.path.basename(ruta)}")
        print(f"  Ruta     : {os.path.abspath(ruta)}")
        print(f"  Tamano   : {stat.st_size:,} bytes")
        print(f"  MD5      : {hashes['md5']}")
        print(f"  SHA-1    : {hashes['sha1']}")
        print(f"  SHA-256  : {hashes['sha256']}")
        print(f"{'='*60}")
        print("\n[!] Registrar estos valores en el informe ANTES de continuar el analisis.")

    elif modo == "directorio":
        ruta = sys.argv[2]
        algoritmo = sys.argv[3] if len(sys.argv) >= 4 else ALGORITMO_POR_DEFECTO

        if not os.path.isdir(ruta):
            print(f"\n[ERROR] No se encuentra el directorio: {ruta}\n")
            sys.exit(1)

        print(f"\n[*] Calculando {algoritmo.upper()} de todos los archivos en: {ruta}\n")
        for raiz, _dirs, archivos in os.walk(ruta):
            for nombre in archivos:
                ruta_abs = os.path.join(raiz, nombre)
                try:
                    h = calcular_hash(ruta_abs, algoritmo)
                    ruta_rel = os.path.relpath(ruta_abs, ruta)
                    print(f"  {h}  {ruta_rel}")
                except Exception as e:
                    print(f"  [ERROR] {nombre}: {e}")

    elif modo == "verificar":
        if len(sys.argv) < 4:
            print("\n[ERROR] Indica: ruta y hash esperado\n")
            _uso()

        ruta          = sys.argv[2]
        hash_esperado = sys.argv[3]
        algoritmo     = sys.argv[4] if len(sys.argv) >= 5 else ALGORITMO_POR_DEFECTO

        if not os.path.isfile(ruta):
            print(f"\n[ERROR] No se encuentra el archivo: {ruta}\n")
            sys.exit(1)

        print(f"\n[*] Verificando integridad ({algoritmo.upper()}): {ruta}")
        hash_actual = calcular_hash(ruta, algoritmo)
        coincide    = hash_actual.lower() == hash_esperado.lower().strip()

        print(f"\n  Hash esperado : {hash_esperado.lower()}")
        print(f"  Hash actual   : {hash_actual}")

        if coincide:
            print(f"\n  [OK] INTEGRIDAD VERIFICADA — La evidencia no ha sido modificada.")
        else:
            print(f"\n  [ALERTA] DISCREPANCIA DETECTADA — La evidencia puede haber sido alterada.")
            print("           Documentar incidencia en el informe pericial.")

    # ── Modo: inventario con hash ───────────────────────────────────────────
    elif modo == "inventario":
        ruta = sys.argv[2]
        if not os.path.isdir(ruta):
            print(f"\n[ERROR] No se encuentra el directorio: {ruta}\n")
            sys.exit(1)
        inventario_con_hash(ruta)

    else:
        print(f"\n[ERROR] Modo desconocido: '{modo}'")
        _uso()
