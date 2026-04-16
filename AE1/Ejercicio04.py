import base64

def base64_a_texto(b64_string):
    return base64.b64decode(b64_string).decode('utf-8')


# Ejecución
if __name__ == "__main__":
    b64_input = (
        "QnV0IGp1c3QgYXMgZHJ1Z3MgaGF2ZSBiZWVuIGFuIGlzc3VlIGluIHBy"
        "b2Zlc3Npb25hbCBzcG9ydCwgZG9waW5nIGlzIGFsc28gYXBwYXJlbnRs"
        "eSBhIGJpZyBwcm9ibGVtIGluIGdyZXlob3VuZCByYWNpbmcuIFRvIHRy"
        "eSBhbmQgY29tYmF0IHRoZSBpc3N1ZSwgYXR0ZW1wdHMgYXJlIG1hZGUg"
        "YnkgdGhlIGF1dGhvcml0aWVzIHRvIGdldCB1cmluZSBzYW1wbGVzIGZy"
        "b20gYWxsIHRoZSBkb2dzIHdobyBoYXZlIHRha2VuIHBhcnQgaW4gdGhl"
        "IHJhY2Uu"
    )

    print(base64_a_texto(b64_input))
