def xor_un_byte(texto, clave):
    """
    Aplica XOR con un solo byte.
    
    Parámetros:
        texto (str)
        clave (int): valor entre 0-255
    
    Retorna:
        bytes
    """
    resultado = bytes([b ^ clave for b in texto.encode()])
    return resultado


# Ejemplo
mensaje = "Hola"
clave = 42

cifrado = xor_un_byte(mensaje, clave)
print("Cifrado:", cifrado)

# Descifrado
descifrado = xor_un_byte(cifrado.decode('latin1'), clave)
print("Descifrado:", descifrado.decode())
