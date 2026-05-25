"""
Ejercicio 5: Diffie-Hellman en Python
Objetivo: Implementar un intercambio seguro de claves usando Diffie-Hellman.
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


def main():
    print("=" * 60)
    print("EJERCICIO 5: Diffie-Hellman en Python")
    print("=" * 60)

    # ── 1. Generar parámetros públicos DH (p y g)
    #    key_size=2048 para seguridad moderna
    print("\n[+] Generando parámetros DH (p, g) — puede tardar unos segundos...")
    parametros = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    numeros = parametros.parameter_numbers()
    p = numeros.p
    g = numeros.g
    print(f"    g = {g}")
    print(f"    p (primeros 60 dígitos) = {str(p)[:60]}...")

    # ── 2 y 3. Simular Alice y Bob: cada uno genera su par de claves
    print("\n[+] Alice genera su par de claves privada/pública...")
    clave_privada_alice = parametros.generate_private_key()
    clave_publica_alice = clave_privada_alice.public_key()

    print("[+] Bob   genera su par de claves privada/pública...")
    clave_privada_bob = parametros.generate_private_key()
    clave_publica_bob = clave_privada_bob.public_key()

    # Mostrar claves públicas (valor y)
    y_alice = clave_publica_alice.public_numbers().y
    y_bob   = clave_publica_bob.public_numbers().y
    print(f"\n    Clave pública Alice (y_A, primeros 60 dígitos): {str(y_alice)[:60]}...")
    print(f"    Clave pública Bob   (y_B, primeros 60 dígitos): {str(y_bob)[:60]}...")

    # ── 4. Intercambio de claves públicas (simulado: cada uno recibe la del otro)

    # ── 5. Cada uno calcula el secreto compartido
    secreto_alice = clave_privada_alice.exchange(clave_publica_bob)
    secreto_bob   = clave_privada_bob.exchange(clave_publica_alice)

    print(f"\n[>] Secreto compartido (Alice): {secreto_alice.hex()[:60]}...")
    print(f"[>] Secreto compartido (Bob)  : {secreto_bob.hex()[:60]}...")

    # ── 6. Verificar que ambos obtienen el mismo secreto
    if secreto_alice == secreto_bob:
        print("\n[✓] Verificación: Alice y Bob han derivado el MISMO secreto compartido.")
    else:
        print("\n[✗] Error: los secretos no coinciden.")


if __name__ == "__main__":
    main()
