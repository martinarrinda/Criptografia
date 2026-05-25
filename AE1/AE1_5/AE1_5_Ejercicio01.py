
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def main():
    # 1. Generar par de claves RSA de 2048 bits
    print("=" * 60)
    print("EJERCICIO 1: Generación y uso básico de RSA")
    print("=" * 60)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    print("\n[+] Par de claves RSA de 2048 bits generado correctamente.")

    # 2. Cifrar un mensaje con la clave pública
    mensaje_original = "Hola, esto es un mensaje secreto cifrado con RSA."
    mensaje_bytes = mensaje_original.encode("utf-8")

    mensaje_cifrado = public_key.encrypt(
        mensaje_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Descifrar el mensaje con la clave privada
    mensaje_descifrado = private_key.decrypt(
        mensaje_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Mostrar resultados y comprobar
    print(f"\n[>] Mensaje original   : {mensaje_original}")
    print(f"\n[>] Mensaje cifrado    : {mensaje_cifrado.hex()}")
    print(f"\n[>] Mensaje descifrado : {mensaje_descifrado.decode('utf-8')}")

    if mensaje_original == mensaje_descifrado.decode("utf-8"):
        print("\n[✓] Verificación: el mensaje descifrado coincide con el original.")
    else:
        print("\n[✗] Error: los mensajes no coinciden.")


if __name__ == "__main__":
    main()
