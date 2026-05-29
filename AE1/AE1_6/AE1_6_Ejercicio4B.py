

import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
import os


# ─────────────────────────────────────────────────────────────────────────────
# REUTILIZAMOS LA LÓGICA DE FIRMA DEL EJERCICIO 4A (autocontenido)
# ─────────────────────────────────────────────────────────────────────────────

TAMANO_SALT_BYTES = 32


def generar_claves_rsa(bits: int = 2048):
    """Genera y retorna un par de claves RSA (privada, pública)."""
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    return clave_privada, clave_privada.public_key()


def calcular_hash_sha256(datos: bytes) -> bytes:
    """Retorna el digest SHA-256 de los datos dados."""
    return hashlib.sha256(datos).digest()


def firmar_pss_simplificado(mensaje: bytes, clave_privada) -> dict:
    """
    Firma un mensaje con RSA-PSS simplificado (versión educativa).

    Retorna un diccionario con: firma, salt, hash_mensaje, hash_final.
    """
    hash_mensaje = calcular_hash_sha256(mensaje)
    salt         = os.urandom(TAMANO_SALT_BYTES)
    combinacion  = hash_mensaje + salt
    hash_final   = calcular_hash_sha256(combinacion)

    firma = clave_privada.sign(
        hash_final,
        rsa_padding.PKCS1v15(),
        hashes.SHA256()
    )

    return {
        "firma":        firma,
        "salt":         salt,
        "hash_mensaje": hash_mensaje,
        "hash_final":   hash_final,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FUNCIÓN PRINCIPAL: VERIFICACIÓN
# ─────────────────────────────────────────────────────────────────────────────

def verificar_pss_simplificado(
    mensaje:       bytes,
    firma:         bytes,
    salt:          bytes,
    clave_publica
) -> bool:
    """
    Verifica una firma RSA-PSS simplificada.

    El proceso es el inverso de la firma:
      1. Recalculamos hash(M) desde el mensaje recibido.
      2. Reproducimos la combinación hash(M)||salt con el salt recibido.
      3. Recalculamos hash_PS = SHA256(combinación).
      4. Verificamos que la firma RSA corresponda a ese hash_PS.

    Args:
        mensaje:      Mensaje original recibido.
        firma:        Firma digital recibida.
        salt:         Salt que se usó al firmar (transmitido junto a la firma).
        clave_publica: Clave pública del firmante.

    Returns:
        True si la firma es válida, False en caso contrario.
    """
    try:
        # ── Paso 1: Recalcular hash del mensaje recibido ─────────────────────
        hash_mensaje_recalculado = calcular_hash_sha256(mensaje)

        # ── Paso 2: Reproducir la combinación usando el MISMO salt ───────────
        combinacion_recalculada = hash_mensaje_recalculado + salt

        # ── Paso 3: Recalcular hash_PS ───────────────────────────────────────
        hash_ps_recalculado = calcular_hash_sha256(combinacion_recalculada)

        # ── Paso 4: Verificar que la firma RSA corresponde al hash_PS ────────
        # verify() lanza InvalidSignature si no coincide
        clave_publica.verify(
            firma,
            hash_ps_recalculado,
            rsa_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True

    except Exception:
        return False


if __name__ == "__main__":
    print("=" * 65)
    print("  EJERCICIO 4B — Implementación simplificada RSA-PSS: VERIFICACIÓN")
    print("=" * 65)

    # ── Preparación: generamos claves y firmamos un mensaje ──────────────────
    print("\n[PREPARACIÓN] Generando claves RSA y firmando el mensaje...")
    clave_privada, clave_publica = generar_claves_rsa(bits=2048)

    mensaje = b"Mensaje de prueba para verificacion RSA-PSS simplificado."
    print(f"    Mensaje: '{mensaje.decode()}'")

    paquete_firma = firmar_pss_simplificado(mensaje, clave_privada)
    firma = paquete_firma["firma"]
    salt  = paquete_firma["salt"]

    print(f"    Salt generado   : {salt.hex()}")
    print(f"    Hash mensaje    : {paquete_firma['hash_mensaje'].hex()}")
    print(f"    Hash combinado  : {paquete_firma['hash_final'].hex()}")
    print(f"    Firma (B64)     : {base64.b64encode(firma).decode()[:60]}...")

    # ─────────────────────────────────────────────────────────────────────────
    # PRUEBA 1: Verificación CORRECTA (mensaje + firma + salt originales)
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  PRUEBA 1 — Verificación con datos CORRECTOS")
    print("─" * 65)

    print("\n  Pasos internos de verificación:")

    # Reproducimos los pasos visualmente
    hash_M_verif = calcular_hash_sha256(mensaje)
    print(f"    Paso 1 — hash(M) recalculado : {hash_M_verif.hex()}")

    combinacion_verif = hash_M_verif + salt
    print(f"    Paso 2 — hash(M)||salt        : {combinacion_verif[:16].hex()}... ({len(combinacion_verif)} bytes)")

    hash_ps_verif = calcular_hash_sha256(combinacion_verif)
    print(f"    Paso 3 — hash_PS recalculado  : {hash_ps_verif.hex()}")
    print(f"    Paso 3 — hash_PS original     : {paquete_firma['hash_final'].hex()}")
    coinciden = hash_ps_verif == paquete_firma["hash_final"]
    print(f"    ¿Coinciden los hashes?        : {'SÍ ✔' if coinciden else 'NO ✗'}")

    resultado1 = verificar_pss_simplificado(mensaje, firma, salt, clave_publica)
    print(f"\n  Resultado final → {'✔ FIRMA VÁLIDA' if resultado1 else '✗ FIRMA INVÁLIDA'}")

    # ─────────────────────────────────────────────────────────────────────────
    # PRUEBA 2: Mensaje alterado (salt y firma sin cambiar)
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  PRUEBA 2 — Verificación con MENSAJE ALTERADO")
    print("─" * 65)

    mensaje_alterado = b"Mensaje de prueba para verificacion RSA-PSS ALTERADO!!"
    print(f"\n  Mensaje alterado: '{mensaje_alterado.decode()}'")

    hash_M_alt = calcular_hash_sha256(mensaje_alterado)
    print(f"    hash(M_alterado) : {hash_M_alt.hex()}")
    print(f"    hash(M_original) : {hash_M_verif.hex()}")
    print(f"    ¿Hashes coinciden? {'SÍ' if hash_M_alt == hash_M_verif else 'NO ✗ (efecto avalancha SHA-256)'}")

    resultado2 = verificar_pss_simplificado(mensaje_alterado, firma, salt, clave_publica)
    print(f"\n  Resultado final → {'✔ FIRMA VÁLIDA' if resultado2 else '✗ FIRMA INVÁLIDA (correcto)'}")

    # ─────────────────────────────────────────────────────────────────────────
    # PRUEBA 3: Salt incorrecto (mensaje y firma sin cambiar)
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  PRUEBA 3 — Verificación con SALT INCORRECTO")
    print("─" * 65)

    salt_incorrecto = os.urandom(TAMANO_SALT_BYTES)
    print(f"\n  Salt original   : {salt.hex()}")
    print(f"  Salt incorrecto : {salt_incorrecto.hex()}")

    resultado3 = verificar_pss_simplificado(mensaje, firma, salt_incorrecto, clave_publica)
    print(f"\n  Resultado final → {'✔ FIRMA VÁLIDA' if resultado3 else '✗ FIRMA INVÁLIDA (correcto)'}")

    # ─────────────────────────────────────────────────────────────────────────
    # DEMOSTRACIÓN DEL PROBABILISMO
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 65)
    print("  DEMOSTRACIÓN — RSA-PSS es PROBABILÍSTICO")
    print("─" * 65)

    print("\n  Firmando el mismo mensaje 3 veces con la misma clave:")
    firmas_generadas = []
    for i in range(1, 4):
        p = firmar_pss_simplificado(mensaje, clave_privada)
        firmas_generadas.append(p["firma"])
        print(f"    Firma {i}: {p['firma'][:12].hex()}...  salt: {p['salt'][:8].hex()}...")

    todas_distintas = len(set(firmas_generadas)) == len(firmas_generadas)
    print(f"\n  ¿Son las 3 firmas distintas? {'SÍ ✔' if todas_distintas else 'NO ✗'}")

    # ─────────────────────────────────────────────────────────────────────────
    # EXPLICACIÓN FINAL
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  EXPLICACIÓN: ¿Por qué RSA-PSS produce firmas distintas?")
    print("=" * 65)
    print("""
  Aunque el MENSAJE y la CLAVE PRIVADA sean idénticos, cada firma usa
  un SALT diferente (bytes aleatorios):

    Firma 1:  SHA256(hash_M || salt_1) → hash_PS_1 → firma_1
    Firma 2:  SHA256(hash_M || salt_2) → hash_PS_2 → firma_2
    Firma 3:  SHA256(hash_M || salt_3) → hash_PS_3 → firma_3

  Como salt_1 ≠ salt_2 ≠ salt_3:
    → hash_PS_1 ≠ hash_PS_2 ≠ hash_PS_3  (efecto avalancha SHA-256)
    → firma_1  ≠ firma_2  ≠ firma_3

  El SALT debe transmitirse junto a la firma para que el verificador
  pueda reproducir exactamente la misma combinación.

  VENTAJA CLAVE:
    Un esquema determinístico (PKCS#1 v1.5) produce siempre la misma
    firma para un mensaje dado, lo que permite ataques de comparación.
    RSA-PSS elimina este problema: dos firmas del mismo mensaje son
    computacionalmente indistinguibles, añadiendo resistencia ante
    ataques de texto cifrado elegido adaptativo (IND-CCA2).
    """)
    print("=" * 65)
    print("  Proceso completado.")
    print("=" * 65)
