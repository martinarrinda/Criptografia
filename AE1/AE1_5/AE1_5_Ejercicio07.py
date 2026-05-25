
import time
from cryptography.hazmat.primitives.asymmetric import ec, dh, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
# ECDH
# ─────────────────────────────────────────────
def demo_ecdh():
    print("\n" + "─" * 50)
    print("  ECDH con curva P-256 (NIST)")
    print("─" * 50)

    # 1. Generar dos pares de claves ECDH
    t0 = time.perf_counter()
    clave_privada_alice = ec.generate_private_key(ec.SECP256R1())
    clave_privada_bob   = ec.generate_private_key(ec.SECP256R1())
    t_gen = time.perf_counter() - t0
    clave_publica_alice = clave_privada_alice.public_key()
    clave_publica_bob   = clave_privada_bob.public_key()

    print(f"\n  [+] Claves ECDH (P-256) generadas en {t_gen*1000:.3f} ms")

    # Tamaños
    priv_bytes_alice = clave_privada_alice.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    pub_bytes_alice = clave_publica_alice.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    print(f"  Tamaño clave privada ECC (PEM): {len(priv_bytes_alice)} bytes")
    print(f"  Tamaño clave pública ECC (PEM): {len(pub_bytes_alice)} bytes")

    # 2. Intercambio de claves públicas (simulado)

    # 3. Calcular secreto compartido
    t0 = time.perf_counter()
    secreto_alice = clave_privada_alice.exchange(ec.ECDH(), clave_publica_bob)
    secreto_bob   = clave_privada_bob.exchange(ec.ECDH(), clave_publica_alice)
    t_exchange = time.perf_counter() - t0

    print(f"\n  [>] Secreto (Alice): {secreto_alice.hex()}")
    print(f"  [>] Secreto (Bob)  : {secreto_bob.hex()}")
    print(f"  Tiempo intercambio : {t_exchange*1000:.3f} ms")

    # 4. Verificar
    if secreto_alice == secreto_bob:
        print("\n  [✓] Ambos obtienen el MISMO secreto compartido.")
    else:
        print("\n  [✗] Error: secretos distintos.")

    return {
        "t_gen_ms": t_gen * 1000,
        "t_exchange_ms": t_exchange * 1000,
        "priv_size": len(priv_bytes_alice),
        "pub_size": len(pub_bytes_alice),
    }


# ─────────────────────────────────────────────
# RSA (para comparativa de tamaños y tiempos)
# ─────────────────────────────────────────────
def demo_rsa():
    print("\n" + "─" * 50)
    print("  RSA-2048 (para comparativa)")
    print("─" * 50)

    t0 = time.perf_counter()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    t_gen = time.perf_counter() - t0
    pub  = priv.public_key()

    priv_bytes = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_bytes  = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    print(f"\n  [+] Claves RSA-2048 generadas en {t_gen*1000:.3f} ms")
    print(f"  Tamaño clave privada RSA (PEM): {len(priv_bytes)} bytes")
    print(f"  Tamaño clave pública  RSA (PEM): {len(pub_bytes)} bytes")

    return {
        "t_gen_ms": t_gen * 1000,
        "priv_size": len(priv_bytes),
        "pub_size": len(pub_bytes),
    }


# ─────────────────────────────────────────────
# DH clásico (para comparativa)
# ─────────────────────────────────────────────
def demo_dh():
    print("\n" + "─" * 50)
    print("  DH clásico 2048 bits (para comparativa)")
    print("─" * 50)

    t0 = time.perf_counter()
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    priv_a = params.generate_private_key()
    priv_b = params.generate_private_key()
    t_gen = time.perf_counter() - t0

    pub_a = priv_a.public_key()
    pub_b = priv_b.public_key()

    pub_bytes_a = pub_a.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    t0 = time.perf_counter()
    s_a = priv_a.exchange(pub_b)
    s_b = priv_b.exchange(pub_a)
    t_exchange = time.perf_counter() - t0

    print(f"\n  [+] Generación DH-2048 en {t_gen*1000:.3f} ms")
    print(f"  Tamaño clave pública DH (PEM): {len(pub_bytes_a)} bytes")
    print(f"  Tiempo intercambio           : {t_exchange*1000:.3f} ms")
    ok = s_a == s_b
    print(f"  [{'✓' if ok else '✗'}] Secretos coinciden: {ok}")

    return {
        "t_gen_ms": t_gen * 1000,
        "t_exchange_ms": t_exchange * 1000,
        "pub_size": len(pub_bytes_a),
    }


# ─────────────────────────────────────────────
# Tabla comparativa
# ─────────────────────────────────────────────
def tabla_comparativa(ecc, rsa_d, dh_d):
    print("\n\n" + "=" * 60)
    print("  TABLA COMPARATIVA: ECC vs RSA vs DH")
    print("=" * 60)
    fmt = "  {:<28} {:>10} {:>10} {:>10}"
    print(fmt.format("Métrica", "ECC P-256", "RSA-2048", "DH-2048"))
    print("  " + "-" * 58)
    print(fmt.format("Nivel de seguridad",      "~128 bits", "~112 bits", "~112 bits"))
    print(fmt.format("Gen. claves (ms)",
                     f"{ecc['t_gen_ms']:.1f}",
                     f"{rsa_d['t_gen_ms']:.1f}",
                     f"{dh_d['t_gen_ms']:.1f}"))
    print(fmt.format("Intercambio (ms)",
                     f"{ecc['t_exchange_ms']:.3f}",
                     "N/A",
                     f"{dh_d['t_exchange_ms']:.3f}"))
    print(fmt.format("Clave pública (bytes PEM)",
                     str(ecc['pub_size']),
                     str(rsa_d['pub_size']),
                     str(dh_d['pub_size'])))
    print(fmt.format("Clave privada (bytes PEM)",
                     str(ecc['priv_size']),
                     str(rsa_d['priv_size']),
                     "—"))
    print("""
  Conclusiones:
  ● ECC ofrece seguridad equivalente o superior con claves mucho
    más pequeñas (≈10× más compactas que RSA).
  ● La generación de claves ECC es significativamente más rápida.
  ● Por eso TLS 1.3 prefiere ECDH sobre DH clásico o RSA para
    el intercambio de claves.
""")


def main():
    print("=" * 60)
    print("EJERCICIO 7: ECDH (Elliptic Curve Diffie-Hellman)")
    print("=" * 60)

    ecc_stats = demo_ecdh()
    rsa_stats = demo_rsa()
    dh_stats  = demo_dh()
    tabla_comparativa(ecc_stats, rsa_stats, dh_stats)


if __name__ == "__main__":
    main()
