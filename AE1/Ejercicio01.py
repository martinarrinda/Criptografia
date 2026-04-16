def texto_a_hex(texto):
    """
    Convierte un texto a su representación hexadecimal.
    
    :param texto: str
    :return: str (hexadecimal)
    """
    return texto.encode('utf-8').hex()


# Ejecución
if __name__ == "__main__":
    texto = "Hola mundo"
    resultado = texto_a_hex(texto)
    print("Hex:", resultado)
