import base64

def texto_a_base64(texto):
    """
    Convierte un string a Base64.
    
    Parámetros:
        texto (str)
    
    Retorna:
        str
    """
    bytes_texto = texto.encode()
    base64_bytes = base64.b64encode(bytes_texto)
    return base64_bytes.decode()


# Ejemplo
mensaje = "Hola"
resultado = texto_a_base64(mensaje)
print("Base64:", resultado)
