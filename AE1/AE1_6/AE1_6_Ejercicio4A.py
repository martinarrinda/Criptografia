

import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────────────────────
TAMANO_SALT_BYTES = 32   # 256 bits de salt aleatorio
TAMANO_CLAVE_RSA  = 2048  # Tamaño de la clave RSA en bits


def generar_claves_rsa(bits: int = TAMANO_CLAVE_RSA):
    """Genera y retorna un par de claves RSA."""
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    return clave_privada, clave_privada.public_key()


def calcular_hash_sha256(datos: bytes) -> bytes:
    """
    Calcula el hash SHA-256 de los datos dados.

    Args:
        datos: Bytes a hashear.

    Returns:
        Digest SHA-256 (32 bytes).
    """
    return hashlib.sha256(datos).digest()


def generar_salt(tamano: int = TAMANO_SALT_BYTES) -> bytes:
    """
    Genera un salt aleatorio criptográficamente seguro.

    Args:
        tamano: Longitud del salt en bytes.

    Returns:
        Bytes aleatorios del tamaño indicado.
    """
    return os.urandom(tamano)


def firma_rsa_pss_simplificada(mensaje: bytes, clave_privada) -> dict:
    """
    Implementa una versión EDUCATIVA simplificada del proceso de firma RSA-PSS.

    El proceso sigue estos pasos:
      1. hash_M  = SHA256(mensaje)
      2. salt    = bytes aleatorios
      3. entrada = hash_M || salt  (concatenación binaria)
      4. hash_PS = SHA256(entrada)
      5. firma   = RSA_raw_sign(hash_PS)

    Args:
        mensaje:       Mensaje a firmar en bytes.
        clave_privada: Clave RSA privada.

    Returns:
        Diccionario con: firma, salt, hash_mensaje, hash_final.
    """
    # ── PASO 1: Hash del mensaje ─────────────────────────────────────────────
    hash_mensaje = calcular_hash_sha256(mensaje)

    # ── PASO 2: Salt aleatorio ───────────────────────────────────────────────
    salt = generar_salt()

    # ── PASO 3: Concatenación hash(M) || salt ────────────────────────────────
    datos_combinados = hash_mensaje + salt  # concatenación directa de bytes

    # ── PASO 4: Hash de la combinación ──────────────────────────────────────
    hash_final = calcular_hash_sha256(datos_combinados)

    # ── PASO 5: Firma RSA sobre el hash final ────────────────────────────────
    # Usamos PKCS1v15 para firmar directamente el hash ya calculado manualmente.
    # PSS real aplicaría sus propios pasos; aquí simplificamos con PKCS1v15
    # para mostrar solo los pasos del PSS de forma didáctica.
    firma = clave_privada.sign(
        hash_final,                         # Firmamos el hash combinado
        rsa_padding.PKCS1v15(),             # Padding RSA básico para esta versión simplificada
        hashes.SHA256()                     # Indica que hash_final ya es SHA256
    )

    return {
        "firma":        firma,
        "salt":         salt,
        "hash_mensaje": hash_mensaje,
        "hash_final":   hash_final,
    }


if __name__ == "__main__":
    print("=" * 65)
    print("  EJERCICIO 4A — Implementación simplificada RSA-PSS: FIRMA")
    print("=" * 65)

    # ── Generación de claves ─────────────────────────────────────────────────
    print("\n[1] Generando claves RSA (2048 bits)...")
    clave_privada, clave_publica = generar_claves_rsa()
    print("    ✔ Claves generadas.")

    # ── Mensaje ──────────────────────────────────────────────────────────────
    mensaje = b"Mensaje de prueba para RSA-PSS simplificado."
    print(f"\n[2] Mensaje original:")
    print(f"    '{mensaje.decode()}'")
    print(f"    Longitud: {len(mensaje)} bytes")

    # ── Proceso de firma simplificado ───────────────────────────────────────
    print("\n[3] Proceso de firma RSA-PSS simplificado (paso a paso):")
    print("─" * 65)

    resultado = firma_rsa_pss_simplificada(mensaje, clave_privada)

    # PASO 1: Hash del mensaje
    print("\n  PASO 1 — Hash SHA-256 del mensaje:")
    print(f"    SHA256(mensaje) = {resultado['hash_mensaje'].hex()}")
    print(f"    Longitud: {len(resultado['hash_mensaje'])} bytes (256 bits)")

    # PASO 2: Salt
    print("\n  PASO 2 — Salt aleatorio generado:")
    print(f"    salt = {resultado['salt'].hex()}")
    print(f"    Longitud: {len(resultado['salt'])} bytes ({len(resultado['salt'])*8} bits)")

    # PASO 3: Concatenación (solo se muestra el resultado)
    datos_combinados = resultado['hash_mensaje'] + resultado['salt']
    print("\n  PASO 3 — Concatenación: hash(M) || salt")
    print(f"    Longitud combinada: {len(datos_combinados)} bytes")
    print(f"    Primeros 16 bytes: {datos_combinados[:16].hex()}...")

    # PASO 4: Hash final
    print("\n  PASO 4 — Hash SHA-256 de la combinación:")
    print(f"    SHA256(hash_M || salt) = {resultado['hash_final'].hex()}")
    print(f"    Longitud: {len(resultado['hash_final'])} bytes (256 bits)")

    # PASO 5: Firma RSA
    firma_b64 = base64.b64encode(resultado['firma']).decode()
    print("\n  PASO 5 — Firma RSA del hash final:")
    print(f"    Firma (Base64): {firma_b64[:72]}...")
    print(f"    Longitud de firma: {len(resultado['firma'])} bytes")

    # ── Efecto del salt: misma clave + mismo mensaje → firma diferente ───────
    print("\n[4] Demostración del PROBABILISMO (ejecutar firma 2 veces):")
    print("─" * 65)
    resultado2 = firma_rsa_pss_simplificada(mensaje, clave_privada)

    print(f"    Firma 1 (inicio): {resultado['firma'][:8].hex()}")
    print(f"    Firma 2 (inicio): {resultado2['firma'][:8].hex()}")
    firmas_distintas = resultado['firma'] != resultado2['firma']
    print(f"    ¿Son distintas?   {'SÍ ✔ (probabilismo del salt)' if firmas_distintas else 'NO ✗'}")

    # ── Guardar para ejercicio 4B ─────────────────────────────────────────────
    print("\n[5] Datos necesarios para la VERIFICACIÓN (Ejercicio 4B):")
    print(f"    → salt         : {resultado['salt'].hex()}")
    print(f"    → firma (B64)  : {firma_b64[:40]}...")
    print("\n    (Estos datos se pasarán al verificador en el ejercicio 4B)")

    print("\n" + "=" * 65)
    print("  Proceso de FIRMA completado. Ver ejercicio_4B.py para verificar.")
    print("=" * 65)
