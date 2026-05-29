

import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding


# ─────────────────────────────────────────────────────────────────────────────
# FUNCIONES ECDSA
# ─────────────────────────────────────────────────────────────────────────────

def generar_claves_ecdsa(curva=ec.SECP256R1()):
    """
    Genera un par de claves ECDSA sobre la curva indicada.

    Args:
        curva: Curva elíptica a utilizar (por defecto P-256 / secp256r1).

    Returns:
        Tupla (clave_privada, clave_pública).
    """
    clave_privada = ec.generate_private_key(curva)
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica


def firmar_ecdsa(mensaje: bytes, clave_privada) -> bytes:
    """
    Firma un mensaje con ECDSA y SHA-256.

    ECDSA produce una firma compuesta por dos enteros (r, s) codificados
    en formato DER (Distinguished Encoding Rules).

    Args:
        mensaje:       Mensaje a firmar en bytes.
        clave_privada: Clave privada ECDSA.

    Returns:
        Firma en formato DER (bytes).
    """
    firma = clave_privada.sign(
        mensaje,
        ec.ECDSA(hashes.SHA256())  # Algoritmo ECDSA con hash SHA-256
    )
    return firma


def verificar_ecdsa(mensaje: bytes, firma: bytes, clave_publica) -> bool:
    """
    Verifica una firma ECDSA.

    Args:
        mensaje:      Mensaje original.
        firma:        Firma DER a verificar.
        clave_publica: Clave pública ECDSA del firmante.

    Returns:
        True si la firma es válida, False en caso contrario.
    """
    try:
        clave_publica.verify(
            firma,
            mensaje,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False


def obtener_tamano_clave_bits(clave_privada) -> int:
    """Retorna el tamaño de la clave en bits (orden de la curva)."""
    return clave_privada.key_size


def decodificar_firma_der(firma_der: bytes) -> tuple:
    """
    Decodifica una firma DER en sus componentes (r, s).

    Args:
        firma_der: Firma en formato DER.

    Returns:
        Tupla (r, s) con los enteros de la firma ECDSA.
    """
    r, s = decode_dss_signature(firma_der)
    return r, s


# ─────────────────────────────────────────────────────────────────────────────
# FUNCIONES RSA (para comparativa)
# ─────────────────────────────────────────────────────────────────────────────

def generar_claves_rsa(bits: int = 2048):
    """Genera un par de claves RSA para la comparativa."""
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    return clave_privada, clave_privada.public_key()


def firmar_rsa(mensaje: bytes, clave_privada) -> bytes:
    """Firma con RSA-PSS para la comparativa de tamaños."""
    return clave_privada.sign(
        mensaje,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


if __name__ == "__main__":
    print("=" * 65)
    print("  EJERCICIO 5 — Firma Digital con ECDSA")
    print("=" * 65)

    # ── Mensaje ──────────────────────────────────────────────────────────────
    mensaje = b"Firmando con ECDSA sobre la curva P-256 (secp256r1)."
    print(f"\nMensaje: '{mensaje.decode()}'")

    # ─────────────────────────────────────────────────────────────────────────
    # SECCIÓN A: ECDSA con P-256
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  [A] ECDSA — Curva P-256 (secp256r1)")
    print("─" * 65)

    # Generación de claves
    print("\n[1] Generando claves ECDSA (P-256)...")
    clave_priv_ec, clave_pub_ec = generar_claves_ecdsa(ec.SECP256R1())

    # Tamaño de la clave
    tamano_clave_bits = obtener_tamano_clave_bits(clave_priv_ec)
    clave_priv_bytes = clave_priv_ec.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    clave_pub_bytes = clave_pub_ec.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(f"    Curva utilizada         : P-256 (secp256r1 / prime256v1)")
    print(f"    Tamaño clave (bits)     : {tamano_clave_bits} bits")
    print(f"    Clave privada (DER)     : {len(clave_priv_bytes)} bytes")
    print(f"    Clave pública (DER)     : {len(clave_pub_bytes)} bytes")

    # Firma
    print("\n[2] Firmando el mensaje con ECDSA + SHA-256...")
    firma_ec = firmar_ecdsa(mensaje, clave_priv_ec)

    print(f"    Firma (Base64): {base64.b64encode(firma_ec).decode()}")
    print(f"    Tamaño de firma: {len(firma_ec)} bytes")

    # Decodificar componentes r, s
    r, s = decodificar_firma_der(firma_ec)
    print(f"\n    Componentes de la firma ECDSA (r, s):")
    print(f"      r = {hex(r)}")
    print(f"      s = {hex(s)}")

    # Verificación
    print("\n[3] Verificando la firma con la clave pública ECDSA...")
    resultado = verificar_ecdsa(mensaje, firma_ec, clave_pub_ec)
    print(f"    Resultado → {'✔ FIRMA VÁLIDA' if resultado else '✗ FIRMA INVÁLIDA'}")

    # Verificación con mensaje alterado
    mensaje_alterado = b"Mensaje completamente diferente."
    resultado_alt = verificar_ecdsa(mensaje_alterado, firma_ec, clave_pub_ec)
    print(f"\n[4] Verificación con mensaje ALTERADO:")
    print(f"    Resultado → {'✔ FIRMA VÁLIDA' if resultado_alt else '✗ FIRMA INVÁLIDA (correcto)'}")

    # ─────────────────────────────────────────────────────────────────────────
    # SECCIÓN B: ECDSA con P-384 y P-521 (comparativa de curvas)
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  [B] Comparativa de curvas ECDSA")
    print("─" * 65)

    curvas = [
        ("P-256  (secp256r1)", ec.SECP256R1()),
        ("P-384  (secp384r1)", ec.SECP384R1()),
        ("P-521  (secp521r1)", ec.SECP521R1()),
    ]

    print(f"\n  {'Curva':<24} {'Bits':>6}  {'Clave priv(B)':>13}  {'Clave pub(B)':>12}  {'Firma(B)':>9}")
    print(f"  {'─'*24} {'─'*6}  {'─'*13}  {'─'*12}  {'─'*9}")

    for nombre_curva, curva_obj in curvas:
        cp, cpub = generar_claves_ecdsa(curva_obj)
        f = firmar_ecdsa(mensaje, cp)
        priv_der = cp.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        pub_der = cpub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"  {nombre_curva:<24} {cp.key_size:>6}  {len(priv_der):>13}  {len(pub_der):>12}  {len(f):>9}")

    # ─────────────────────────────────────────────────────────────────────────
    # SECCIÓN C: Comparativa ECDSA vs RSA
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  [C] Comparativa ECDSA vs RSA (mismo nivel de seguridad ~128 bits)")
    print("─" * 65)

    # ECDSA P-256
    cp256, cpub256 = generar_claves_ecdsa(ec.SECP256R1())
    firma_ecdsa_256 = firmar_ecdsa(mensaje, cp256)
    priv_ec_der = cp256.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_ec_der = cpub256.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # RSA 3072 (equivalente a P-256 en seguridad)
    clave_priv_rsa, _ = generar_claves_rsa(bits=3072)
    firma_rsa_3072 = firmar_rsa(mensaje, clave_priv_rsa)
    priv_rsa_der = clave_priv_rsa.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_rsa_der = clave_priv_rsa.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(f"\n  {'Algoritmo':<22} {'Bits seg.':>9}  {'Clave priv(B)':>13}  {'Clave pub(B)':>12}  {'Firma(B)':>9}")
    print(f"  {'─'*22} {'─'*9}  {'─'*13}  {'─'*12}  {'─'*9}")
    print(f"  {'ECDSA P-256':<22} {'~128':>9}  {len(priv_ec_der):>13}  {len(pub_ec_der):>12}  {len(firma_ecdsa_256):>9}")
    print(f"  {'RSA-3072':<22} {'~128':>9}  {len(priv_rsa_der):>13}  {len(pub_rsa_der):>12}  {len(firma_rsa_3072):>9}")

    ratio_priv  = len(priv_rsa_der)  / len(priv_ec_der)
    ratio_pub   = len(pub_rsa_der)   / len(pub_ec_der)
    ratio_firma = len(firma_rsa_3072) / len(firma_ecdsa_256)
    print(f"\n  → RSA-3072 usa {ratio_priv:.0f}x más bytes en clave privada que ECDSA P-256.")
    print(f"  → RSA-3072 usa {ratio_pub:.0f}x más bytes en clave pública  que ECDSA P-256.")
    print(f"  → RSA-3072 usa {ratio_firma:.0f}x más bytes en firma          que ECDSA P-256.")

    print("""
  RESUMEN COMPARATIVO RSA vs ECDSA:
  ────────────────────────────────────────────────────────────
  ECDSA:
    ✔ Claves y firmas mucho más pequeñas → menor ancho de banda
    ✔ Generación de claves y firma más rápida
    ✔ Ideal para dispositivos IoT, tarjetas inteligentes, TLS
    ✗ Implementación más compleja (aritmética de curvas elípticas)
    ✗ Vulnerable a reutilización de nonce (problema k)

  RSA:
    ✔ Algoritmo más conocido y ampliamente soportado
    ✔ Firmas determinísticas con PKCS#1 v1.5 (más simple de impl.)
    ✗ Claves y firmas mucho más grandes
    ✗ Más lento en operaciones de clave privada (firma/descifrado)
    ✗ Necesitará claves enormes en la era post-cuántica
    """)
    print("=" * 65)
    print("  Proceso completado.")
    print("=" * 65)
