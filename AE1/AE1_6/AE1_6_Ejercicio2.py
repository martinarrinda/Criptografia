
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generar_claves_rsa(bits: int = 2048):
    """Genera y retorna un par de claves RSA (privada, pública)."""
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    return clave_privada, clave_privada.public_key()


def firmar(mensaje: bytes, clave_privada) -> bytes:
    """Firma un mensaje con RSA-PSS + SHA-256."""
    return clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verificar(mensaje: bytes, firma: bytes, clave_publica) -> bool:
    """
    Verifica la firma RSA-PSS de un mensaje.

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
    except Exception as e:
        return False


def alterar_firma(firma: bytes, posicion: int = 0, nuevo_valor: int = 0xFF) -> bytes:
    """
    Altera un byte de la firma en una posición dada.

    Args:
        firma:       Firma original en bytes.
        posicion:    Índice del byte a modificar.
        nuevo_valor: Nuevo valor del byte (0-255).

    Returns:
        Firma alterada como bytes.
    """
    firma_lista = bytearray(firma)
    valor_original = firma_lista[posicion]
    # Nos aseguramos de que el byte cambia realmente
    firma_lista[posicion] = (valor_original + 1) % 256 if nuevo_valor == valor_original else nuevo_valor
    return bytes(firma_lista)


def mostrar_resultado(etiqueta: str, es_valida: bool) -> None:
    """Muestra el resultado de la verificación con formato."""
    simbolo = "✔" if es_valida else "✗"
    estado = "VÁLIDA  ✔" if es_valida else "INVÁLIDA ✗"
    print(f"    Resultado → Firma {estado}")


if __name__ == "__main__":
    print("=" * 65)
    print("  EJERCICIO 2 — Alteración de una Firma Digital")
    print("=" * 65)

    # ----------------------------------------------------------------
    # Configuración inicial: claves y mensaje
    # ----------------------------------------------------------------
    print("\n[PREPARACIÓN] Generando claves RSA (2048 bits)...")
    clave_privada, clave_publica = generar_claves_rsa()
    print("    ✔ Claves generadas.")

    mensaje_original = b"Este es el mensaje original que vamos a firmar y alterar."
    print(f"\n    Mensaje: '{mensaje_original.decode()}'")

    # Firma original
    firma_original = firmar(mensaje_original, clave_privada)
    print(f"\n    Firma original (primeros 32 bytes en hex): {firma_original[:32].hex()}...")

    # ----------------------------------------------------------------
    # PRUEBA 1: Verificación de la firma ORIGINAL (debe ser válida)
    # ----------------------------------------------------------------
    print("\n" + "─" * 65)
    print("  PRUEBA 1 — Verificación de la firma ORIGINAL")
    print("─" * 65)
    resultado = verificar(mensaje_original, firma_original, clave_publica)
    mostrar_resultado("original", resultado)
    assert resultado, "ERROR: La firma original debería ser válida."

    # ----------------------------------------------------------------
    # PRUEBA 2: Alteración de bytes de la FIRMA
    # ----------------------------------------------------------------
    print("\n" + "─" * 65)
    print("  PRUEBA 2 — Modificación de la FIRMA (manteniendo el mensaje)")
    print("─" * 65)

    # Alteramos 3 bytes en distintas posiciones de la firma
    firma_alterada = bytearray(firma_original)
    posiciones_alteradas = [0, 50, 100]
    for pos in posiciones_alteradas:
        valor_nuevo = (firma_alterada[pos] + 77) % 256  # XOR con valor arbitrario
        firma_alterada[pos] = valor_nuevo

    firma_alterada = bytes(firma_alterada)

    print(f"\n    Bytes alterados en posiciones: {posiciones_alteradas}")
    print(f"    Firma original  (inicio): {firma_original[:8].hex()}")
    print(f"    Firma modificada (inicio): {firma_alterada[:8].hex()}")

    resultado_firma_alterada = verificar(mensaje_original, firma_alterada, clave_publica)
    mostrar_resultado("alterada", resultado_firma_alterada)
    assert not resultado_firma_alterada, "ERROR: La firma alterada no debería ser válida."

    # ----------------------------------------------------------------
    # PRUEBA 3: Alteración del MENSAJE (manteniendo la firma original)
    # ----------------------------------------------------------------
    print("\n" + "─" * 65)
    print("  PRUEBA 3 — Modificación del MENSAJE (manteniendo la firma)")
    print("─" * 65)

    mensaje_modificado = b"Este es el mensaje MODIFICADO que ya no coincide con la firma."
    print(f"\n    Mensaje original : '{mensaje_original.decode()}'")
    print(f"    Mensaje modificado: '{mensaje_modificado.decode()}'")

    resultado_mensaje_mod = verificar(mensaje_modificado, firma_original, clave_publica)
    mostrar_resultado("con mensaje modificado", resultado_mensaje_mod)
    assert not resultado_mensaje_mod, "ERROR: La firma no debería ser válida con mensaje alterado."

    # ----------------------------------------------------------------
    # EXPLICACIÓN FINAL
    # ----------------------------------------------------------------
    print("\n" + "=" * 65)
    print("  ANÁLISIS DE RESULTADOS")
    print("=" * 65)
    print("""
  ¿Por qué deja de ser válida la firma?
  ──────────────────────────────────────
  La firma digital es el cifrado (con la clave PRIVADA) del hash del
  mensaje. La verificación consiste en:

    1. Descifrar la firma con la clave PÚBLICA → hash_firmado
    2. Calcular el hash del mensaje recibido   → hash_calculado
    3. Comparar: hash_firmado == hash_calculado

  Si se modifica la firma:
    → Al descifrarla, el hash_firmado resultante es basura.
    → hash_firmado ≠ hash_calculado → INVÁLIDA.

  Si se modifica el mensaje:
    → El hash_calculado cambia completamente (efecto avalancha del SHA-256).
    → hash_firmado ≠ hash_calculado → INVÁLIDA.

  PROPIEDAD GARANTIZADA: INTEGRIDAD
  La firma digital asegura que el contenido NO ha sido alterado
  desde que fue firmado. Cualquier modificación, por mínima que sea,
  rompe la verificación.
    """)
    print("=" * 65)
    print("  Proceso completado.")
    print("=" * 65)
