
import time


# ─────────────────────────────────────────────
# Parte 1 — Método ingenuo
# ─────────────────────────────────────────────
def pow_naive(B: int, e: int, N: int) -> tuple[int, int]:
    """
    Calcula B^e mod N usando multiplicaciones iterativas (método ingenuo).
    Devuelve (resultado, número_de_multiplicaciones).
    """
    resultado = 1
    mults = 0
    for _ in range(e):
        resultado = (resultado * B) % N
        mults += 1
    return resultado, mults


# ─────────────────────────────────────────────
# Parte 2 — Exponenciación rápida (square-and-multiply)
# ─────────────────────────────────────────────
def pow_fast(B: int, e: int, N: int) -> tuple[int, int]:
    """
    Calcula B^e mod N usando el algoritmo square-and-multiply.
    Devuelve (resultado, número_de_multiplicaciones).
    """
    resultado = 1
    base = B % N
    mults = 0
    exponente = e

    while exponente > 0:
        if exponente % 2 == 1:          # bit actual es 1 → multiply
            resultado = (resultado * base) % N
            mults += 1
        base = (base * base) % N        # square siempre
        mults += 1
        exponente //= 2

    return resultado, mults


# ─────────────────────────────────────────────
# Parte 3 — Comparación
# ─────────────────────────────────────────────
def comparar(B: int, e: int, N: int, label: str = ""):
    print(f"\n{'─'*50}")
    if label:
        print(f"  Caso: {label}")
    print(f"  B = {B}, e = {e}, N = {N}")

    # Método ingenuo (solo para exponentes razonablemente pequeños)
    MAX_NAIVE = 10_000_000
    if e <= MAX_NAIVE:
        t0 = time.perf_counter()
        res_naive, mults_naive = pow_naive(B, e, N)
        t_naive = time.perf_counter() - t0
        print(f"\n  [Ingenuo]")
        print(f"    Resultado     : {res_naive}")
        print(f"    Multiplicaciones: {mults_naive:,}")
        print(f"    Tiempo        : {t_naive:.6f} s")
    else:
        print(f"\n  [Ingenuo] — omitido (e={e:,} > límite {MAX_NAIVE:,})")
        res_naive = None

    # Método rápido
    t0 = time.perf_counter()
    res_fast, mults_fast = pow_fast(B, e, N)
    t_fast = time.perf_counter() - t0
    print(f"\n  [Square-and-Multiply]")
    print(f"    Resultado     : {res_fast}")
    print(f"    Multiplicaciones: {mults_fast:,}  (≈ 2·log₂(e) = {2*e.bit_length()})")
    print(f"    Tiempo        : {t_fast:.6f} s")

    # Verificación con pow() de Python
    res_builtin = pow(B, e, N)
    print(f"\n  [pow() Python]  : {res_builtin}")
    print(f"  [✓] Coincide fast == pow(): {res_fast == res_builtin}")


def main():
    print("=" * 60)
    print("EJERCICIO 3: Exponenciación modular eficiente")
    print("=" * 60)

    # Caso pequeño (podemos usar los dos métodos)
    comparar(B=5, e=1_000_000, N=998_244_353, label="exponente moderado (1 millón)")

    # Caso grande (solo fast y builtin)
    B_grande = 123456789
    e_grande = 2**127 - 1          # primo de Mersenne
    N_grande = 2**128 - 159        # primo grande
    comparar(B=B_grande, e=e_grande, N=N_grande, label="exponente enorme (2^127-1)")


if __name__ == "__main__":
    main()
