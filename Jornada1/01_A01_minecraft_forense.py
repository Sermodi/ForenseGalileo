#!/usr/bin/env python3
"""
minecraft_forense.py
====================
EJERCICIO EXTRA J1-B — Jornada 1: Informática Forense con Python
Formación GalileoForense

Descripción
-----------
Análisis forense de saves de Minecraft. Los ficheros de guardado
de Minecraft (.dat) son artefactos digitales reales que contienen:
  - Última posición conocida del jugador (x, y, z)
  - Inventario completo con ítems
  - Tiempo total jugado (en ticks)
  - Seed del mundo (puede revelar el servidor o mapa)
  - Historial de dimensiones visitadas (Overworld, Nether, End)
  - Timestamp de última modificación

Formato NBT (Named Binary Tag): formato binario comprimido con
gzip creado por Notch para Minecraft. Parseable con Python puro
o con la librería nbtlib.

Casos reales de uso forense:
  - Verificar si un jugador estuvo online durante un horario
    (correlacionar con un coartada)
  - Detectar coordenadas de bases ocultas en servidores
  - Auditar uso de cheats o modificaciones (inventario imposible)
  - Recuperar historial de actividad de una cuenta robada

Uso
---
    python minecraft_forense.py --generar-demo     # Crea save simulado
    python minecraft_forense.py level.dat          # Analiza save real
    python minecraft_forense.py --carpeta <ruta>   # Analiza múltiples saves

Dependencias
------------
    pip install nbtlib   (si no está disponible usa el parser propio)

Autor   : SergioM.
Versión : 1.0
Fecha   : 2026-04-5
"""

import sys
import gzip
import struct
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# PARSER NBT PROPIO (sin dependencias externas)
# Solo implementa los tipos necesarios para level.dat y playerdata
# ---------------------------------------------------------------------------

NBT_TIPOS = {
    0: "TAG_End",
    1: "TAG_Byte",
    2: "TAG_Short",
    3: "TAG_Int",
    4: "TAG_Long",
    5: "TAG_Float",
    6: "TAG_Double",
    7: "TAG_Byte_Array",
    8: "TAG_String",
    9: "TAG_List",
    10: "TAG_Compound",
    11: "TAG_Int_Array",
    12: "TAG_Long_Array",
}


class NBTParser:
    """Parser NBT minimalista para extraer campos forenses clave."""

    def __init__(self, datos: bytes):
        self.datos = datos
        self.pos = 0

    def leer_bytes(self, n: int) -> bytes:
        chunk = self.datos[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def leer_tipo(self, tipo: int):
        if tipo == 1:   # Byte
            return struct.unpack(">b", self.leer_bytes(1))[0]
        elif tipo == 2: # Short
            return struct.unpack(">h", self.leer_bytes(2))[0]
        elif tipo == 3: # Int
            return struct.unpack(">i", self.leer_bytes(4))[0]
        elif tipo == 4: # Long
            return struct.unpack(">q", self.leer_bytes(8))[0]
        elif tipo == 5: # Float
            return struct.unpack(">f", self.leer_bytes(4))[0]
        elif tipo == 6: # Double
            return struct.unpack(">d", self.leer_bytes(8))[0]
        elif tipo == 7: # Byte Array
            n = struct.unpack(">i", self.leer_bytes(4))[0]
            return self.leer_bytes(n)
        elif tipo == 8: # String
            n = struct.unpack(">H", self.leer_bytes(2))[0]
            return self.leer_bytes(n).decode("utf-8", errors="replace")
        elif tipo == 9: # List
            tipo_elem = struct.unpack(">b", self.leer_bytes(1))[0]
            n = struct.unpack(">i", self.leer_bytes(4))[0]
            return [self.leer_tipo(tipo_elem) for _ in range(n)]
        elif tipo == 10: # Compound
            return self.leer_compound()
        elif tipo == 11: # Int Array
            n = struct.unpack(">i", self.leer_bytes(4))[0]
            return [struct.unpack(">i", self.leer_bytes(4))[0] for _ in range(n)]
        elif tipo == 12: # Long Array
            n = struct.unpack(">i", self.leer_bytes(4))[0]
            return [struct.unpack(">q", self.leer_bytes(8))[0] for _ in range(n)]
        else:
            return None

    def leer_nombre(self) -> str:
        n = struct.unpack(">H", self.leer_bytes(2))[0]
        return self.leer_bytes(n).decode("utf-8", errors="replace")

    def leer_compound(self) -> dict:
        resultado = {}
        while self.pos < len(self.datos):
            tipo = struct.unpack(">b", self.leer_bytes(1))[0]
            if tipo == 0:  # TAG_End
                break
            nombre = self.leer_nombre()
            valor = self.leer_tipo(tipo)
            resultado[nombre] = valor
        return resultado

    def parsear(self) -> dict:
        """Parsea el fichero NBT completo. Devuelve el compound raíz."""
        tipo_raiz = struct.unpack(">b", self.leer_bytes(1))[0]
        self.leer_nombre()  # nombre de la raíz (generalmente vacío)
        return self.leer_compound()


def generar_save_demo() -> None:
    """
    Genera un fichero level.dat simulado en formato NBT/gzip
    con datos forenses interesantes para analizar en clase.
    """
    # Construimos el NBT manualmente (binary big-endian)
    def tag_string(nombre: str, valor: str) -> bytes:
        nb = nombre.encode("utf-8")
        vb = valor.encode("utf-8")
        return (b"\x08" + struct.pack(">H", len(nb)) + nb +
                struct.pack(">H", len(vb)) + vb)

    def tag_long(nombre: str, valor: int) -> bytes:
        nb = nombre.encode("utf-8")
        return b"\x04" + struct.pack(">H", len(nb)) + nb + struct.pack(">q", valor)

    def tag_int(nombre: str, valor: int) -> bytes:
        nb = nombre.encode("utf-8")
        return b"\x03" + struct.pack(">H", len(nb)) + nb + struct.pack(">i", valor)

    def tag_double(nombre: str, valor: float) -> bytes:
        nb = nombre.encode("utf-8")
        return b"\x06" + struct.pack(">H", len(nb)) + nb + struct.pack(">d", valor)

    # Datos del jugador sospechoso
    # Último online: 2026-03-15 02:14 UTC (coincide con el caso ACME)
    ultimo_online_ms = int(datetime(2026, 3, 15, 2, 14, 0, tzinfo=timezone.utc).timestamp() * 1000)
    ticks_jugados    = 72000 * 8  # ~8 horas en ticks (20 ticks/seg, 72000 ticks/hora)

    # Coordenadas: cerca del Nether portal → base oculta
    pos_x = -1847.5
    pos_z =  3021.3
    pos_y =   64.0

    # Construir compound Data
    datos_nbt = b"\x0a"  # TAG_Compound
    datos_nbt += struct.pack(">H", 4) + b"Data"  # nombre "Data"

    datos_nbt += tag_string("LevelName", "mundo_secreto_acme")
    datos_nbt += tag_long("LastPlayed", ultimo_online_ms)
    datos_nbt += tag_long("RandomSeed", -3129871423847561234)  # seed del mundo
    datos_nbt += tag_long("Time", ticks_jugados)
    datos_nbt += tag_int("GameType", 0)           # 0=Survival, 1=Creative, 3=Spectator
    datos_nbt += tag_string("generatorName", "default")
    datos_nbt += tag_string("Player.UUID", "a7f3c291-1b2d-4e5f-8a9b-0c1d2e3f4a5b")

    # Posición del jugador (en el Nether → coordenadas reales * 8)
    datos_nbt += tag_double("Player.Pos.X", pos_x)
    datos_nbt += tag_double("Player.Pos.Y", pos_y)
    datos_nbt += tag_double("Player.Pos.Z", pos_z)
    datos_nbt += tag_int("Player.Dimension", -1)  # -1=Nether, 0=Overworld, 1=End

    # Items sospechosos en el inventario
    datos_nbt += tag_string("Player.Inventory.Note",
                            "hacked_client_items:xray_potion=64,speed_hack=1")

    datos_nbt += b"\x00"  # TAG_End del compound Data
    datos_nbt += b"\x00"  # TAG_End del compound raíz

    # Cabecera NBT raíz
    nbt_completo = b"\x0a\x00\x00" + datos_nbt

    # Comprimir con gzip (así lo hace Minecraft)
    directorio = Path("evidencias_minecraft")
    directorio.mkdir(exist_ok=True)
    ruta_dat = directorio / "level.dat"

    with gzip.open(str(ruta_dat), "wb") as f:
        f.write(nbt_completo)

    sha256 = hashlib.sha256(ruta_dat.read_bytes()).hexdigest()
    print(f"[OK] Save generado: {ruta_dat}")
    print(f"     SHA-256: {sha256}")
    print(f"\nSiguiente paso:")
    print(f"  python minecraft_forense.py {ruta_dat}")


# ---------------------------------------------------------------------------
# ANÁLISIS FORENSE
# ---------------------------------------------------------------------------

DIMENSIONES = {-1: "Nether", 0: "Overworld", 1: "The End"}
GAME_TYPES   = {0: "Survival", 1: "Creative", 2: "Hardcore", 3: "Spectator"}

def ticks_a_tiempo(ticks: int) -> str:
    """Convierte ticks de juego a tiempo legible."""
    segundos = ticks // 20
    h, resto = divmod(segundos, 3600)
    m, s = divmod(resto, 60)
    return f"{h}h {m}m {s}s"

def analizar_save(ruta: str) -> None:
    """Analiza un fichero level.dat de Minecraft y extrae artefactos forenses."""

    ruta_p = Path(ruta)
    if not ruta_p.exists():
        print(f"[ERROR] Fichero no encontrado: {ruta}")
        return

    # Hash de integridad
    sha256 = hashlib.sha256(ruta_p.read_bytes()).hexdigest()
    print("\n" + "="*65)
    print("  ANÁLISIS FORENSE — SAVE DE MINECRAFT")
    print("="*65)
    print(f"\n  Fichero  : {ruta_p.name}")
    print(f"  Tamaño   : {ruta_p.stat().st_size:,} bytes")
    print(f"  SHA-256  : {sha256[:32]}...")

    # Descomprimir y parsear NBT
    try:
        with gzip.open(ruta, "rb") as f:
            datos = f.read()
        print(f"  Compresión: gzip ({ruta_p.stat().st_size} → {len(datos)} bytes descomprimidos)")
    except Exception as e:
        print(f"  [!] No es gzip estándar, intentando sin comprimir...")
        datos = ruta_p.read_bytes()

    try:
        parser = NBTParser(datos)
        nbt = parser.parsear()
    except Exception as e:
        print(f"  [ERROR] No se pudo parsear el NBT: {e}")
        return

    # Extraer campo Data (compound principal)
    data = nbt.get("Data", nbt)

    print("\n" + "-"*65)
    print("  METADATOS DEL MUNDO")
    print("-"*65)

    nombre = data.get("LevelName", "desconocido")
    seed   = data.get("RandomSeed", "desconocido")
    gt_id  = data.get("GameType", 0)
    gt     = GAME_TYPES.get(gt_id, f"Desconocido ({gt_id})")
    ticks  = data.get("Time", 0)
    tiempo = ticks_a_tiempo(ticks) if ticks else "N/A"

    print(f"\n  Nombre del mundo : {nombre}")
    print(f"  Modo de juego    : {gt}")
    print(f"  Tiempo jugado    : {tiempo}")
    print(f"  Seed del mundo   : {seed}")
    if seed and seed != "desconocido":
        print(f"    → El seed identifica de forma única el mapa generado.")
        print(f"    → Permite reproducir exactamente el mismo mundo.")

    # Último acceso
    last_played = data.get("LastPlayed")
    if last_played:
        try:
            ts = datetime.fromtimestamp(last_played / 1000, tz=timezone.utc)
            print(f"\n  Último acceso    : {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"    → ¿Coincide con algún evento del caso?")
        except Exception:
            print(f"\n  LastPlayed (raw) : {last_played}")

    # Posición del jugador
    print("\n" + "-"*65)
    print("  POSICIÓN DEL JUGADOR")
    print("-"*65)

    pos_x   = data.get("Player.Pos.X")
    pos_y   = data.get("Player.Pos.Y")
    pos_z   = data.get("Player.Pos.Z")
    dim_id  = data.get("Player.Dimension", 0)
    dim     = DIMENSIONES.get(dim_id, f"Dimensión {dim_id}")
    uuid    = data.get("Player.UUID", "no disponible")

    if pos_x is not None:
        print(f"\n  Dimensión : {dim}")
        print(f"  X: {pos_x:.2f}  Y: {pos_y:.2f}  Z: {pos_z:.2f}")
        print(f"  UUID      : {uuid}")
        if dim_id == -1:
            ow_x = pos_x * 8
            ow_z = pos_z * 8
            print(f"\n  📌 En el Nether las coordenadas se multiplican por 8 en Overworld:")
            print(f"     Coordenadas reales: X={ow_x:.0f} Z={ow_z:.0f}")

    # Inventario — detectar ítems imposibles o de trampas
    print("\n" + "-"*65)
    print("  ANÁLISIS DE INVENTARIO")
    print("-"*65)
    inv_nota = data.get("Player.Inventory.Note", "")
    if inv_nota:
        print(f"\n  ⚠️  Indicadores de cliente hackeado / cheats:")
        for item in inv_nota.split(","):
            print(f"    • {item.strip()}")
        print(f"\n  → La presencia de ítems imposibles (x64 de pociones,")
        print(f"    velocidad infinita, etc.) indica uso de hacks.")

    print("\n" + "="*65)


# ---------------------------------------------------------------------------
# PUNTO DE ENTRADA
# ---------------------------------------------------------------------------

def main():
    if "--generar-demo" in sys.argv:
        generar_save_demo()
        return

    if "--carpeta" in sys.argv:
        idx = sys.argv.index("--carpeta")
        carpeta = Path(sys.argv[idx + 1])
        saves = list(carpeta.rglob("level.dat")) + list(carpeta.rglob("*.dat"))
        print(f"  Encontrados {len(saves)} ficheros .dat")
        for s in saves:
            analizar_save(str(s))
        return

    if len(sys.argv) < 2:
        print("Uso: python minecraft_forense.py --generar-demo")
        print("     python minecraft_forense.py <level.dat>")
        print("     python minecraft_forense.py --carpeta <ruta_saves>")
        sys.exit(1)

    analizar_save(sys.argv[1])


if __name__ == "__main__":
    main()
