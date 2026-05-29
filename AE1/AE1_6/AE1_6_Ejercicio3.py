

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generar_claves_rsa(nombre: str, bits: int = 2048):
    """
    Genera un par de claves RSA para un participante.

    Args:
        nombre: Nombre del participante (solo para mensajes en pantalla).
        bits:   Tamaño de la clave en bits.

    Returns:
        Tupla (clave_privada, clave_pública).
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    clave_publica = clave_privada.public_key()
    print(f"    ✔ Claves RSA de {nombre} generadas ({bits} bits).")
    return clave_privada, clave_publica


def firmar(mensaje: bytes, clave_privada, firmante: str) -> bytes:
    """
    Firma un mensaje con la clave privada del firmante.

    Args:
        mensaje:       Mensaje a firmar en bytes.
        clave_privada: Clave privada del firmante.
        firmante:      Nombre del firmante (para mensajes).

    Returns:
        Firma digital en bytes.
    """
    firma = clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f"    ✔ {firmante} firma el mensaje (primeros 16 bytes): {firma[:16].hex()}...")
    return firma


def verificar(mensaje: bytes, firma: bytes, clave_publica, clave_propietario: str) -> bool:
    """
    Verifica una firma con la clave pública indicada.

    Args:
        mensaje:           Mensaje recibido.
        firma:             Firma a verificar.
        clave_publica:     Clave pública con la que verificar.
        clave_propietario: Nombre del propietario de la clave (para mensajes).

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
        return False


def mostrar_verificacion(descripcion: str, resultado: bool) -> None:
    """Muestra el resultado de una verificación con formato claro."""
    if resultado:
        print(f"    ✔ {descripcion}: VÁLIDA  ← La firma pertenece a este firmante.")
    else:
        print(f"    ✗ {descripcion}: INVÁLIDA ← La firma NO pertenece a este firmante.")


if __name__ == "__main__":
    print("=" * 65)
    print("  EJERCICIO 3 — Ataque de interceptación y refirma")
    print("  Participantes: Alice (emisor), Mallory (atacante), Bob (receptor)")
    print("=" * 65)

    # ─────────────────────────────────────────────────────────────
    # FASE 1: Generación de claves
    # ─────────────────────────────────────────────────────────────
    print("\n[FASE 1] Generación de claves RSA para cada participante")
    print("─" * 65)
    clave_privada_alice, clave_publica_alice = generar_claves_rsa("Alice")
    clave_privada_mallory, clave_publica_mallory = generar_claves_rsa("Mallory")
    # Bob no necesita clave privada en este escenario (solo verifica)

    # ─────────────────────────────────────────────────────────────
    # FASE 2: Alice crea y firma el mensaje
    # ─────────────────────────────────────────────────────────────
    print("\n[FASE 2] Alice crea y firma el mensaje")
    print("─" * 65)

    mensaje_alice = b"Hola Bob, soy Alice. Transfiere 1000 EUR a mi cuenta."
    print(f"    Mensaje de Alice: '{mensaje_alice.decode()}'")

    firma_alice = firmar(mensaje_alice, clave_privada_alice, "Alice")

    # ─────────────────────────────────────────────────────────────
    # FASE 3: Mallory intercepta y refirma
    # ─────────────────────────────────────────────────────────────
    print("\n[FASE 3] Mallory intercepta el canal de comunicación")
    print("─" * 65)
    print("    ⚠ Mallory ha capturado: (mensaje, firma_Alice)")
    print(f"    Mallory conoce el mensaje: '{mensaje_alice.decode()}'")
    print("    Mallory NO puede descifrar la firma de Alice (no tiene su clave privada).")
    print("    Mallory DESCARTA la firma de Alice y genera la SUYA PROPIA.")

    # Mallory firma el mismo mensaje con su propia clave privada
    firma_mallory = firmar(mensaje_alice, clave_privada_mallory, "Mallory")

    print("\n    Mallory envía a Bob: (mismo mensaje, firma_Mallory)")
    print("    → Bob recibe lo que parece ser un mensaje de Alice,")
    print("      pero con la firma de Mallory.")

    # ─────────────────────────────────────────────────────────────
    # FASE 4: Bob verifica
    # ─────────────────────────────────────────────────────────────
    print("\n[FASE 4] Bob verifica las firmas")
    print("─" * 65)
    print(f"    Mensaje recibido: '{mensaje_alice.decode()}'")
    print()

    # Bob verifica la firma de Mallory con la clave pública de ALICE
    print("  [4.1] Bob verifica la firma recibida (de Mallory) con clave pública de ALICE:")
    resultado_con_alice = verificar(
        mensaje_alice, firma_mallory, clave_publica_alice,
        "clave pública de Alice"
    )
    mostrar_verificacion("Verificación con clave de Alice", resultado_con_alice)

    # Bob verifica la firma de Mallory con la clave pública de MALLORY
    print()
    print("  [4.2] Bob verifica la firma recibida (de Mallory) con clave pública de MALLORY:")
    resultado_con_mallory = verificar(
        mensaje_alice, firma_mallory, clave_publica_mallory,
        "clave pública de Mallory"
    )
    mostrar_verificacion("Verificación con clave de Mallory", resultado_con_mallory)

    # Referencia: verificación de la firma ORIGINAL de Alice (para comparar)
    print()
    print("  [4.3] Referencia: firma ORIGINAL de Alice verificada con su propia clave:")
    resultado_original = verificar(
        mensaje_alice, firma_alice, clave_publica_alice,
        "clave pública de Alice"
    )
    mostrar_verificacion("Verificación firma original de Alice", resultado_original)

    # ─────────────────────────────────────────────────────────────
    # ANÁLISIS FINAL
    # ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  ANÁLISIS DEL ATAQUE")
    print("=" * 65)
    print("""
  RESUMEN DE VERIFICACIONES:
  ───────────────────────────────────────────────────────────
  Firma de Mallory + clave de Alice   → INVÁLIDA  (correcto)
  Firma de Mallory + clave de Mallory → VÁLIDA    (alerta!)
  Firma de Alice   + clave de Alice   → VÁLIDA    (legítima)

  ¿QUÉ APRENDEMOS?
  ─────────────────
  1. Mallory puede crear firmas válidas, pero solo con SU propia clave.
     Falsificar la firma de Alice sin su clave privada es computacionalmente
     imposible (seguridad RSA).

  2. El peligro real ocurre si Bob NO sabe qué clave pública pertenece a Alice.
     Si Mallory logra que Bob use su clave pública creyendo que es la de Alice,
     el ataque tiene éxito (ataque Man-in-the-Middle con sustitución de clave).

  3. SOLUCIÓN → Infraestructura de Clave Pública (PKI):
     Los certificados X.509 ligan criptográficamente una identidad (Alice)
     a una clave pública, firmados por una Autoridad Certificadora (CA) de
     confianza. Bob valida el certificado antes de usar la clave pública.

  PROPIEDAD GARANTIZADA (si la clave es auténtica): AUTENTICIDAD
    """)
    print("=" * 65)
    print("  Proceso completado.")
    print("=" * 65)
