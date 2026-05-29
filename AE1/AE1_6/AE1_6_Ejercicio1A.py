

import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generar_claves_rsa(bits: int = 2048):
    """
    Genera un par de claves RSA (privada y pública).

    Args:
        bits: Tamaño de la clave en bits (mínimo recomendado: 2048).

    Returns:
        Tupla (clave_privada, clave_pública).
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,  # Exponente público estándar (e)
        key_size=bits,          # Longitud del módulo en bits
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica


def firmar_mensaje(mensaje: bytes, clave_privada) -> bytes:
    """
    Firma un mensaje con RSA-PSS y SHA-256.

    Args:
        mensaje:       Mensaje a firmar en bytes.
        clave_privada: Clave RSA privada del firmante.

    Returns:
        Bytes de la firma digital.
    """
    firma = clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),   # Función generadora de máscara
            salt_length=padding.PSS.MAX_LENGTH    # Salt al máximo (más seguro)
        ),
        hashes.SHA256()  # Algoritmo de hash para el mensaje
    )
    return firma


def verificar_firma(mensaje: bytes, firma: bytes, clave_publica) -> bool:
    """
    Verifica una firma RSA-PSS.

    Args:
        mensaje:      Mensaje original en bytes.
        firma:        Firma digital a verificar.
        clave_publica: Clave RSA pública del firmante.

    Returns:
        True si la firma es válida, False en caso contrario.
    """
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
        # verify() lanza una excepción si la firma no es válida
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("  EJERCICIO 1A — Firma Digital con RSA-PSS")
    print("=" * 60)

    # ----------------------------------------------------------------
    # 1. Generación del par de claves RSA de 2048 bits
    # ----------------------------------------------------------------
    print("\n[1] Generando par de claves RSA (2048 bits)...")
    clave_privada, clave_publica = generar_claves_rsa(bits=2048)
    print("    ✔ Claves generadas correctamente.")

    # ----------------------------------------------------------------
    # 2. Mensaje a firmar
    # ----------------------------------------------------------------
    mensaje_texto = "Hola, este es un mensaje firmado digitalmente con RSA-PSS."
    mensaje_bytes = mensaje_texto.encode("utf-8")

    print(f"\n[2] Mensaje original:")
    print(f"    '{mensaje_texto}'")

    # ----------------------------------------------------------------
    # 3. Firma del mensaje con la clave privada
    # ----------------------------------------------------------------
    print("\n[3] Firmando el mensaje con la clave privada...")
    firma = firmar_mensaje(mensaje_bytes, clave_privada)

    # Codificamos en Base64 para mostrarla de forma legible
    firma_b64 = base64.b64encode(firma).decode("utf-8")
    print(f"\n[4] Firma digital (Base64):")
    print(f"    {firma_b64[:80]}...")
    print(f"    (longitud total: {len(firma)} bytes)")

    # ----------------------------------------------------------------
    # 4. Verificación de la firma con la clave pública
    # ----------------------------------------------------------------
    print("\n[5] Verificando la firma con la clave pública...")
    es_valida = verificar_firma(mensaje_bytes, firma, clave_publica)

    if es_valida:
        print("    ✔ FIRMA VÁLIDA: el mensaje es auténtico e íntegro.")
    else:
        print("    ✗ FIRMA INVÁLIDA: el mensaje ha sido alterado o la clave es incorrecta.")

    print("\n" + "=" * 60)
    print("  Proceso completado.")
    print("=" * 60)