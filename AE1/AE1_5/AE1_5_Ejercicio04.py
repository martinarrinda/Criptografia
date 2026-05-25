
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def cifrado_hibrido(mensaje: str, public_key, private_key):
    """
    Cifra un mensaje con AES-256-CTR y protege la clave AES con RSA-OAEP.
    Devuelve un diccionario con todos los componentes del paquete cifrado.
    """
    # ── Paso 1: Generar clave AES-256 aleatoria (32 bytes = 256 bits)
    aes_key = os.urandom(32)

    # ── Paso 2: Cifrar el mensaje con AES-256-CTR
    nonce = os.urandom(16)  # nonce/IV de 128 bits para CTR
    cifrador = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    encryptor = cifrador.encryptor()
    mensaje_cifrado = encryptor.update(mensaje.encode("utf-8")) + encryptor.finalize()

    # ── Paso 3: Cifrar la clave AES con RSA-OAEP (clave pública)
    aes_key_cifrada = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "aes_key": aes_key,
        "nonce": nonce,
        "aes_key_cifrada": aes_key_cifrada,
        "mensaje_cifrado": mensaje_cifrado,
    }


def descifrado_hibrido(paquete: dict, private_key) -> str:
    """
    Descifra el paquete híbrido usando la clave privada RSA.
    """
    # ── Paso 4: Descifrar la clave AES con RSA (clave privada)
    aes_key_recuperada = private_key.decrypt(
        paquete["aes_key_cifrada"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # ── Paso 5: Descifrar el mensaje con AES-256-CTR
    cifrador = Cipher(algorithms.AES(aes_key_recuperada), modes.CTR(paquete["nonce"]))
    decryptor = cifrador.decryptor()
    mensaje_descifrado = decryptor.update(paquete["mensaje_cifrado"]) + decryptor.finalize()

    return mensaje_descifrado.decode("utf-8")


def main():
    print("=" * 60)
    print("EJERCICIO 4: Criptografía híbrida (RSA + AES)")
    print("=" * 60)

    # Generar par de claves RSA 2048 bits
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    print("\n[+] Par de claves RSA-2048 generado.")

    mensaje = "Este mensaje viaja protegido con criptografía híbrida RSA+AES, como en HTTPS."
    print(f"\n[>] Mensaje original:\n    {mensaje}")

    # Cifrado
    paquete = cifrado_hibrido(mensaje, public_key, private_key)

    print(f"\n[>] Clave AES generada (hex)        : {paquete['aes_key'].hex()}")
    print(f"[>] Nonce/IV (hex)                  : {paquete['nonce'].hex()}")
    print(f"[>] Clave AES cifrada con RSA (hex) : {paquete['aes_key_cifrada'].hex()[:80]}...")
    print(f"[>] Mensaje cifrado con AES (hex)   : {paquete['mensaje_cifrado'].hex()}")

    # Descifrado
    mensaje_recuperado = descifrado_hibrido(paquete, private_key)
    print(f"\n[>] Mensaje descifrado final:\n    {mensaje_recuperado}")

    # Verificación
    if mensaje == mensaje_recuperado:
        print("\n[✓] Verificación: el mensaje descifrado coincide con el original.")
    else:
        print("\n[✗] Error: los mensajes no coinciden.")


if __name__ == "__main__":
    main()
