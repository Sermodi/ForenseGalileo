#!/usr/bin/env python3
"""
stego_lsb.py
============
EJERCICIO EXTRA J1-A — Jornada 1: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Esteganografía LSB (Least Significant Bit):
  - OCULTAR: esconde un mensaje de texto dentro de una imagen PNG
    modificando el bit menos significativo de cada canal de color.
  - DETECTAR: analiza una imagen sospechosa para determinar si
    contiene datos ocultos mediante análisis estadístico del LSB.
  - EXTRAER: recupera el mensaje oculto de una imagen portadora.

La esteganografía LSB es invisible al ojo humano pero detectable
mediante análisis forense. Es una técnica real usada en casos de
espionaje corporativo y distribución de malware encubierto.

Uso
---
    # Ocultar un mensaje en una imagen
    python stego_lsb.py --ocultar --imagen foto.png --mensaje "texto secreto" --salida foto_stego.png

    # Detectar si una imagen tiene datos ocultos
    python stego_lsb.py --detectar --imagen foto_sospechosa.png

    # Extraer el mensaje oculto
    python stego_lsb.py --extraer --imagen foto_stego.png

    # Generar imágenes de demostración para el ejercicio
    python stego_lsb.py --demo

Dependencias
------------
    pip install Pillow

Autor   : SergioM.
Versión : 1.0
Fecha   : 2026-04-10
"""

import sys
import hashlib
import struct
from pathlib import Path
from collections import Counter

try:
    from PIL import Image
except ImportError:
    print("\n[ERROR] Pillow no está instalado.")
    print("        Instálalo con: pip install Pillow\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# CONSTANTES
# ---------------------------------------------------------------------------

# Cabecera mágica que embebemos para detectar nuestra esteganografía
MAGIC = b"GLFST1"      # GalileoForense Stego v1
BITS_POR_BYTE = 8
CANALES = 3            # R, G, B (ignoramos alpha si existe)


# ---------------------------------------------------------------------------
# UTILIDADES BITS
# ---------------------------------------------------------------------------

def texto_a_bits(texto: str) -> list:
    """Convierte una cadena de texto a una lista de bits (0/1)."""
    resultado = []
    for byte in texto.encode("utf-8"):
        for i in range(7, -1, -1):
            resultado.append((byte >> i) & 1)
    return resultado

def bits_a_bytes(bits: list) -> bytes:
    """Convierte una lista de bits de vuelta a bytes."""
    resultado = []
    for i in range(0, len(bits), 8):
        grupo = bits[i:i+8]
        if len(grupo) == 8:
            valor = 0
            for bit in grupo:
                valor = (valor << 1) | bit
            resultado.append(valor)
    return bytes(resultado)


# ---------------------------------------------------------------------------
# OCULTAR MENSAJE (LSB encoding)
# ---------------------------------------------------------------------------

def ocultar_mensaje(ruta_imagen: str, mensaje: str, ruta_salida: str) -> None:
    """
    Oculta un mensaje en una imagen PNG modificando el LSB de cada
    canal de color de los píxeles. El ojo humano no detecta cambios
    de 1 bit en el valor de un color (0-255).

    Estructura del payload embebido:
        [MAGIC 6B] [longitud mensaje 4B little-endian] [mensaje UTF-8]
    """
    img = Image.open(ruta_imagen).convert("RGB")
    pixeles = list(img.getdata())
    ancho, alto = img.size
    capacidad_bits = ancho * alto * CANALES

    # Construir payload completo
    msg_bytes = mensaje.encode("utf-8")
    payload = MAGIC + struct.pack("<I", len(msg_bytes)) + msg_bytes
    bits_payload = texto_a_bits(payload.decode("latin-1"))

    if len(bits_payload) > capacidad_bits:
        print(f"[ERROR] Imagen demasiado pequeña. "
              f"Necesitas {len(bits_payload)} bits, "
              f"disponibles: {capacidad_bits}")
        sys.exit(1)

    # Incrustar bits en los LSB de cada canal RGB
    nuevos_pixeles = []
    bit_idx = 0
    for r, g, b in pixeles:
        canales = [r, g, b]
        nuevos = []
        for canal in canales:
            if bit_idx < len(bits_payload):
                # Reemplazar el bit menos significativo
                canal = (canal & 0xFE) | bits_payload[bit_idx]
                bit_idx += 1
            nuevos.append(canal)
        nuevos_pixeles.append(tuple(nuevos))

    # Guardar imagen modificada (PNG para no perder datos por compresión)
    img_nueva = Image.new("RGB", (ancho, alto))
    img_nueva.putdata(nuevos_pixeles)
    img_nueva.save(ruta_salida, "PNG")

    sha256 = hashlib.sha256(Path(ruta_salida).read_bytes()).hexdigest()
    print(f"\n  [OK] Mensaje ocultado en: {ruta_salida}")
    print(f"  Píxeles modificados : {bit_idx // CANALES} de {ancho * alto}")
    print(f"  Bits usados         : {bit_idx} de {capacidad_bits} "
          f"({100 * bit_idx / capacidad_bits:.2f}% de capacidad)")
    print(f"  SHA-256             : {sha256[:32]}...")
    print(f"\n  A simple vista la imagen es IDÉNTICA a la original.")
    print(f"  ¿Serías capaz de detectar la diferencia sin herramientas?")


# ---------------------------------------------------------------------------
# EXTRAER MENSAJE
# ---------------------------------------------------------------------------

def extraer_mensaje(ruta_imagen: str) -> str | None:
    """
    Extrae el mensaje oculto de una imagen portadora leyendo
    el LSB de cada canal RGB de los píxeles.
    """
    img = Image.open(ruta_imagen).convert("RGB")
    pixeles = list(img.getdata())

    # Leer todos los LSB
    bits = []
    for r, g, b in pixeles:
        for canal in [r, g, b]:
            bits.append(canal & 1)

    # Verificar cabecera mágica (primeros 6 bytes = 48 bits)
    cabecera_bits = bits[:48]
    cabecera = bits_a_bytes(cabecera_bits)
    if cabecera != MAGIC:
        print("  [!] No se encontró cabecera de esteganografía LSB conocida.")
        return None

    # Leer longitud del mensaje (siguiente 4 bytes = 32 bits)
    longitud_bits = bits[48:80]
    longitud = struct.unpack("<I", bits_a_bytes(longitud_bits))[0]

    # Leer el mensaje
    inicio_msg = 80
    fin_msg = inicio_msg + longitud * 8
    msg_bits = bits[inicio_msg:fin_msg]
    msg_bytes = bits_a_bytes(msg_bits)

    try:
        mensaje = msg_bytes.decode("utf-8")
    except UnicodeDecodeError:
        mensaje = msg_bytes.decode("latin-1")

    return mensaje


# ---------------------------------------------------------------------------
# ANÁLISIS ESTADÍSTICO (detección sin conocer el mensaje)
# ---------------------------------------------------------------------------

def analizar_distribucion_lsb(ruta_imagen: str) -> None:
    """
    Analiza la distribución estadística del LSB de cada canal.
    En imágenes naturales, los LSB siguen una distribución pseudo-aleatoria
    pero con cierta correlación espacial.
    En imágenes con LSB steganografía, los bits son más uniformemente
    distribuidos (entropía más alta), lo que es detectable.
    """
    img = Image.open(ruta_imagen).convert("RGB")
    pixeles = list(img.getdata())

    lsb_r = [p[0] & 1 for p in pixeles]
    lsb_g = [p[1] & 1 for p in pixeles]
    lsb_b = [p[2] & 1 for p in pixeles]

    def estadisticas_canal(bits, nombre):
        unos = sum(bits)
        ceros = len(bits) - unos
        ratio = unos / len(bits) if bits else 0

        # Chi-squared test simplificado:
        # En una distribución aleatoria perfecta, ratio ≈ 0.5
        # Desviación significativa puede indicar manipulación
        desviacion = abs(ratio - 0.5)
        sospechoso = desviacion < 0.02  # muy cerca de 0.5 → posible stego

        print(f"    Canal {nombre}: 0={ceros:>6} / 1={unos:>6} "
              f"→ ratio={ratio:.4f}  "
              f"{'⚠️  DISTRIBUCIÓN UNIFORME (posible stego)' if sospechoso else '✔  Normal'}")

    print(f"\n  Análisis LSB — {Path(ruta_imagen).name}")
    print(f"  Total píxeles: {len(pixeles)}")
    print(f"\n  Distribución de bits LSB por canal:")
    estadisticas_canal(lsb_r, "R")
    estadisticas_canal(lsb_g, "G")
    estadisticas_canal(lsb_b, "B")

    # Detección directa de cabecera mágica
    bits_totales = []
    for r, g, b in pixeles:
        bits_totales.extend([r & 1, g & 1, b & 1])

    cabecera = bits_a_bytes(bits_totales[:48])
    if cabecera == MAGIC:
        print(f"\n  🔴 CABECERA MÁGICA DETECTADA: imagen contiene datos ocultos (formato GalileoForense LSB)")
    else:
        print(f"\n  ✔ No se detectó cabecera conocida en los primeros 48 bits.")


# ---------------------------------------------------------------------------
# GENERADOR DE DEMO
# ---------------------------------------------------------------------------

def generar_demo() -> None:
    """
    Crea una imagen de prueba limpia y otra con mensaje oculto
    para usar en el ejercicio de clase.
    """
    directorio = Path("evidencias_stego")
    directorio.mkdir(exist_ok=True)

    # Crear imagen de 400x300 con gradiente (simula foto real)
    img = Image.new("RGB", (400, 300))
    pixeles = []
    for y in range(300):
        for x in range(400):
            r = int(255 * x / 400)
            g = int(255 * y / 300)
            b = int(255 * (x + y) / 700)
            pixeles.append((r, g, b))
    img.putdata(pixeles)

    ruta_limpia = str(directorio / "imagen_limpia.png")
    ruta_stego  = str(directorio / "imagen_sospechosa.png")

    img.save(ruta_limpia, "PNG")
    sha_limpia = hashlib.sha256(Path(ruta_limpia).read_bytes()).hexdigest()

    # Ocultar mensaje en la segunda imagen
    mensaje_secreto = (
        "OPERACION ECLIPSE | Reunión: 15/03/2026 02:00 UTC | "
        "Coordenadas: 40.4534 -3.6890 | Contraseña: G4l1l30_Fr34k"
    )
    ocultar_mensaje(ruta_limpia, mensaje_secreto, ruta_stego)

    print(f"\n  Imagen limpia    : {ruta_limpia}  SHA-256: {sha_limpia[:16]}...")
    print(f"\n  ¡Ahora tienes dos imágenes visualmente idénticas!")
    print(f"  Tu misión: detectar y extraer el mensaje oculto.")
    print(f"\n  Comandos del ejercicio:")
    print(f"    python stego_lsb.py --detectar --imagen {ruta_stego}")
    print(f"    python stego_lsb.py --extraer --imagen {ruta_stego}")


# ---------------------------------------------------------------------------
# PUNTO DE ENTRADA
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    if "--demo" in args:
        generar_demo()

    elif "--ocultar" in args:
        img = args[args.index("--imagen") + 1]
        msg = args[args.index("--mensaje") + 1]
        sal = args[args.index("--salida") + 1]
        ocultar_mensaje(img, msg, sal)

    elif "--detectar" in args:
        img = args[args.index("--imagen") + 1]
        analizar_distribucion_lsb(img)

    elif "--extraer" in args:
        img = args[args.index("--imagen") + 1]
        print(f"\n  Extrayendo mensaje oculto de: {img}")
        msg = extraer_mensaje(img)
        if msg:
            print(f"\n  ✅ Mensaje recuperado:")
            print(f"  {'─'*50}")
            print(f"  {msg}")
            print(f"  {'─'*50}")
        else:
            print("  No se encontró mensaje.")

    else:
        print("Uso:")
        print("  python stego_lsb.py --demo")
        print("  python stego_lsb.py --detectar --imagen <fichero.png>")
        print("  python stego_lsb.py --extraer  --imagen <fichero.png>")
        print("  python stego_lsb.py --ocultar  --imagen <orig.png> --mensaje 'texto' --salida <out.png>")


if __name__ == "__main__":
    main()
