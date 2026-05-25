
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    print("=" * 60)
    print("EJERCICIO 2: Analizando una clave RSA")
    print("=" * 60)

    # 1. Generar par de claves RSA de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # 2. Extraer parámetros
    private_numbers = private_key.private_numbers()
    public_numbers = public_key.public_numbers()  # equivalente a private_numbers.public_numbers

    p = private_numbers.p
    q = private_numbers.q
    d = private_numbers.d
    e = public_numbers.e
    N = public_numbers.n

    print("\n--- Parámetros de la clave RSA ---")
    print(f"\n[e] Exponente público        : {e}")
    print(f"\n[N] Módulo RSA (primeros 80 dígitos): {str(N)[:80]}...")
    print(f"\n[p] Primer primo (primeros 40 dígitos): {str(p)[:40]}...")
    print(f"\n[q] Segundo primo (primeros 40 dígitos): {str(q)[:40]}...")
    print(f"\n[d] Exponente privado (primeros 40 dígitos): {str(d)[:40]}...")

    # 3. Verificar N = p * q
    print("\n--- Verificación matemática ---")
    verificacion = (p * q == N)
    print(f"\n[✓] N == p * q : {verificacion}")

    # 4. Explicación de cada parámetro
    print("\n--- Descripción de los parámetros ---")
    descripciones = {
        "e (exponente público)": (
            "Se usa para cifrar mensajes. Es público y conocido por todos. "
            "Valor estándar: 65537 (eficiente y seguro)."
        ),
        "d (exponente privado)": (
            "Se usa para descifrar mensajes. Debe mantenerse en secreto absoluto. "
            "Es el inverso modular de e respecto a φ(N)."
        ),
        "p (primer primo)": (
            "Uno de los dos números primos grandes cuyo producto forma N. "
            "Debe permanecer secreto; su conocimiento permite factorizar N."
        ),
        "q (segundo primo)": (
            "El segundo número primo grande. Junto con p, forma la base de la "
            "seguridad RSA. También debe mantenerse secreto."
        ),
        "N (módulo RSA)": (
            "Producto de p y q. Es público y forma parte de la clave pública. "
            "Su seguridad reside en la dificultad de factorizarlo."
        ),
    }
    for param, desc in descripciones.items():
        print(f"\n  [{param}]\n  → {desc}")

    # --- Parte opcional: cifrado manual con la fórmula RSA ---
    print("\n--- Parte opcional: cifrado/descifrado manual con fórmula RSA ---")
    m = 42  # mensaje numérico pequeño (debe ser < N)
    c = pow(m, e, N)   # c = m^e mod N
    m_recuperado = pow(c, d, N)  # m = c^d mod N

    print(f"\n  Mensaje original (m)   : {m}")
    print(f"  Mensaje cifrado (c)    : {str(c)[:60]}...")
    print(f"  Mensaje recuperado (m) : {m_recuperado}")
    print(f"\n  [✓] Coincide: {m == m_recuperado}")


if __name__ == "__main__":
    main()
