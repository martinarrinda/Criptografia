
def main():
    print("=" * 60)
    print("EJERCICIO 6: Diffie-Hellman manual")
    print("=" * 60)

    # Parámetros públicos
    p = 23
    g = 5

    # Claves privadas
    a = 6   # clave privada de Alice
    b = 15  # clave privada de Bob

    print(f"\n  Parámetros públicos : p = {p}, g = {g}")
    print(f"  Clave privada Alice : a = {a}")
    print(f"  Clave privada Bob   : b = {b}")

    # ── 1. Clave pública de Alice: A = g^a mod p
    A = pow(g, a, p)
    print(f"\n--- Cálculo de claves públicas ---")
    print(f"\n  [1] Clave pública Alice: A = g^a mod p = {g}^{a} mod {p} = {A}")

    # ── 2. Clave pública de Bob: B = g^b mod p
    B = pow(g, b, p)
    print(f"  [2] Clave pública Bob  : B = g^b mod p = {g}^{b} mod {p} = {B}")

    # ── 3. Secreto compartido calculado por Alice: s = B^a mod p
    s_alice = pow(B, a, p)
    print(f"\n--- Cálculo del secreto compartido ---")
    print(f"\n  [3] Secreto (Alice): s = B^a mod p = {B}^{a} mod {p} = {s_alice}")

    # ── 4. Secreto compartido calculado por Bob: s = A^b mod p
    s_bob = pow(A, b, p)
    print(f"  [4] Secreto (Bob)  : s = A^b mod p = {A}^{b} mod {p} = {s_bob}")

    # ── Verificación
    print("\n--- Verificación ---")
    if s_alice == s_bob:
        print(f"\n  [✓] Ambos obtienen el mismo secreto compartido: s = {s_alice}")
    else:
        print(f"\n  [✗] Error: secretos diferentes ({s_alice} vs {s_bob})")

    # ── Verificación con pow() integrado
    print("\n--- Comprobación con pow() integrado de Python ---")
    A_check   = pow(g, a, p)
    B_check   = pow(g, b, p)
    sA_check  = pow(B_check, a, p)
    sB_check  = pow(A_check, b, p)
    print(f"  A = pow({g},{a},{p}) = {A_check}   ✓" if A_check == A else f"  A ✗")
    print(f"  B = pow({g},{b},{p}) = {B_check}  ✓" if B_check == B else f"  B ✗")
    print(f"  s_Alice = pow({B_check},{a},{p}) = {sA_check}   ✓" if sA_check == s_alice else f"  s_Alice ✗")
    print(f"  s_Bob   = pow({A_check},{b},{p}) = {sB_check}   ✓" if sB_check == s_bob else f"  s_Bob ✗")


if __name__ == "__main__":
    main()