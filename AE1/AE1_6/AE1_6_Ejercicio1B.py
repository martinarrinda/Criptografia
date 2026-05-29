
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ─────────────────────────────────────────────────────────────────────────────
# RUTAS DE LOS FICHEROS PEM
# ─────────────────────────────────────────────────────────────────────────────
RUTA_CLAVE_PRIVADA = "clave_privada.pem"
RUTA_CLAVE_PUBLICA = "clave_publica.pem"


def generar_y_guardar_claves(bits: int = 2048) -> None:
    """
    Genera un par de claves RSA y las guarda en ficheros PEM.

    La clave privada se guarda sin cifrar (NoEncryption) para simplificar
    el ejercicio. En producción se usaría BestAvailableEncryption(contraseña).

    Args:
        bits: Tamaño de la clave en bits.
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    clave_publica = clave_privada.public_key()

    # Serializar clave privada en formato PEM (PKCS#8)
    pem_privada = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Sin contraseña
    )

    # Serializar clave pública en formato PEM (SubjectPublicKeyInfo)
    pem_publica = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Escribir los ficheros en disco
    with open(RUTA_CLAVE_PRIVADA, "wb") as f:
        f.write(pem_privada)

    with open(RUTA_CLAVE_PUBLICA, "wb") as f:
        f.write(pem_publica)

    print(f"    ✔ Clave privada guardada en: {RUTA_CLAVE_PRIVADA}")
    print(f"    ✔ Clave pública  guardada en: {RUTA_CLAVE_PUBLICA}")


def cargar_clave_privada(ruta: str):
    """
    Carga una clave privada RSA desde un fichero PEM.

    Args:
        ruta: Ruta al fichero PEM de la clave privada.

    Returns:
        Objeto de clave privada RSA.
    """
    with open(ruta, "rb") as f:
        contenido_pem = f.read()

    clave_privada = serialization.load_pem_private_key(
        contenido_pem,
        password=None  # Sin contraseña; si estuviera cifrada, indicar aquí
    )
    return clave_privada


def cargar_clave_publica(ruta: str):
    """
    Carga una clave pública RSA desde un fichero PEM.

    Args:
        ruta: Ruta al fichero PEM de la clave pública.

    Returns:
        Objeto de clave pública RSA.
    """
    with open(ruta, "rb") as f:
        contenido_pem = f.read()

    clave_publica = serialization.load_pem_public_key(contenido_pem)
    return clave_publica


def firmar_mensaje(mensaje: bytes, clave_privada) -> bytes:
    """Firma un mensaje con RSA-PSS y SHA-256."""
    return clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verificar_firma(mensaje: bytes, firma: bytes, clave_publica) -> bool:
    """Verifica una firma RSA-PSS; retorna True si es válida."""
    try:
        clave_publica.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def mostrar_contenido_pem(ruta: str, descripcion: str) -> None:
    """Muestra las primeras y últimas líneas del fichero PEM."""
    with open(ruta, "r") as f:
        lineas = f.readlines()
    print(f"\n    [{descripcion}] ({len(lineas)} líneas)")
    print(f"    {lineas[0].strip()}")
    print(f"    ... ({len(lineas) - 2} líneas de datos Base64) ...")
    print(f"    {lineas[-1].strip()}")


if __name__ == "__main__":
    print("=" * 60)
    print("  EJERCICIO 1B — RSA-PSS con Persistencia de Claves PEM")
    print("=" * 60)

    # ----------------------------------------------------------------
    # 1. Generación y guardado de claves en disco
    # ----------------------------------------------------------------
    print("\n[1] Generando y guardando claves RSA (2048 bits) en PEM...")
    generar_y_guardar_claves(bits=2048)

    # Mostrar vista previa del contenido PEM
    mostrar_contenido_pem(RUTA_CLAVE_PRIVADA, "Clave Privada PEM")
    mostrar_contenido_pem(RUTA_CLAVE_PUBLICA, "Clave Pública PEM")

    # ----------------------------------------------------------------
    # 2. Carga de claves desde disco (simulando una segunda sesión)
    # ----------------------------------------------------------------
    print("\n[2] Cargando claves desde disco...")
    clave_privada_cargada = cargar_clave_privada(RUTA_CLAVE_PRIVADA)
    clave_publica_cargada = cargar_clave_publica(RUTA_CLAVE_PUBLICA)
    print("    ✔ Claves cargadas correctamente desde los ficheros PEM.")

    # Mostrar tamaño de la clave cargada
    tamano_bits = clave_privada_cargada.key_size
    print(f"    ✔ Tamaño de la clave cargada: {tamano_bits} bits")

    # ----------------------------------------------------------------
    # 3. Mensaje a firmar
    # ----------------------------------------------------------------
    mensaje_texto = "Este mensaje será firmado con claves cargadas desde disco."
    mensaje_bytes = mensaje_texto.encode("utf-8")
    print(f"\n[3] Mensaje: '{mensaje_texto}'")

    # ----------------------------------------------------------------
    # 4. Firma con la clave privada cargada
    # ----------------------------------------------------------------
    print("\n[4] Firmando con la clave privada cargada desde disco...")
    firma = firmar_mensaje(mensaje_bytes, clave_privada_cargada)
    firma_b64 = base64.b64encode(firma).decode("utf-8")
    print(f"    Firma (Base64): {firma_b64[:80]}...")

    # ----------------------------------------------------------------
    # 5. Verificación con la clave pública cargada
    # ----------------------------------------------------------------
    print("\n[5] Verificando con la clave pública cargada desde disco...")
    es_valida = verificar_firma(mensaje_bytes, firma, clave_publica_cargada)

    if es_valida:
        print("    ✔ FIRMA VÁLIDA: las claves cargadas funcionan correctamente.")
    else:
        print("    ✗ FIRMA INVÁLIDA: error inesperado.")

    # ----------------------------------------------------------------
    # Limpieza opcional de ficheros temporales
    # ----------------------------------------------------------------
    print("\n[6] Ficheros PEM generados (disponibles en el directorio actual):")
    for ruta in [RUTA_CLAVE_PRIVADA, RUTA_CLAVE_PUBLICA]:
        size_kb = os.path.getsize(ruta) / 1024
        print(f"    • {ruta} ({size_kb:.1f} KB)")

    print("\n" + "=" * 60)
    print("  Proceso completado.")
    print("=" * 60)
