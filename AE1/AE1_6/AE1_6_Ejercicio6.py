
import ssl
import socket
import datetime
import base64
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────────────────────
SITIO_DEFECTO  = "www.google.com"
PUERTO_HTTPS   = 443
TIMEOUT_SEG    = 10
FICHERO_PEM    = "certificado_servidor.pem"


def obtener_cadena_certificados(host: str, puerto: int = PUERTO_HTTPS) -> list:
    """
    Se conecta a un servidor HTTPS y obtiene la cadena completa de certificados.

    Args:
        host:   Nombre del servidor (ej: "www.google.com").
        puerto: Puerto HTTPS (normalmente 443).

    Returns:
        Lista de objetos x509.Certificate (leaf primero, raíz último).
    """
    # Contexto SSL que solicita la cadena completa de certificados
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = True
    contexto.verify_mode = ssl.CERT_REQUIRED

    certificados_der = []

    with socket.create_connection((host, puerto), timeout=TIMEOUT_SEG) as sock:
        with contexto.wrap_socket(sock, server_hostname=host) as ssock:
            # Obtener el certificado del servidor (formato DER binario)
            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der:
                certificados_der.append(cert_der)

            # Intentar obtener la cadena completa si el servidor la envía
            try:
                cadena_der = ssock.get_verified_chain()
                if cadena_der:
                    certificados_der = [cert.public_bytes(ssl.ENCODING_DER)
                                        if hasattr(cert, 'public_bytes')
                                        else cert
                                        for cert in cadena_der]
            except AttributeError:
                # get_verified_chain() disponible en Python 3.10+
                pass

    # Convertir de DER a objetos x509
    certificados = []
    for der in certificados_der:
        try:
            cert_obj = x509.load_der_x509_certificate(der)
            certificados.append((cert_obj, der))
        except Exception:
            pass

    return certificados


def obtener_cert_simple(host: str, puerto: int = PUERTO_HTTPS,
                        verificar: bool = True) -> tuple:
    """
    Obtiene únicamente el certificado del servidor (sin cadena completa).
    Método alternativo más compatible con todas las versiones de Python.

    Args:
        host:     Nombre del servidor.
        puerto:   Puerto HTTPS.
        verificar: Si False, desactiva la verificación del certificado
                   (útil en entornos de laboratorio/proxy). ⚠ NO usar en producción.

    Returns:
        Tupla (cert_x509, cert_der).
    """
    if verificar:
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = True
        contexto.verify_mode = ssl.CERT_REQUIRED
    else:
        # MODO SIN VERIFICACIÓN — solo para entornos de laboratorio
        print("    ⚠  AVISO: verificación SSL desactivada (modo laboratorio).")
        print("       En producción NUNCA se debe desactivar la verificación.")
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, puerto), timeout=TIMEOUT_SEG) as sock:
        with contexto.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)

    if not cert_der:
        raise ValueError("El servidor no devolvió certificado en formato DER.")

    cert_x509 = x509.load_der_x509_certificate(cert_der)
    return cert_x509, cert_der


def extraer_atributo_name(name: x509.Name, oid) -> str:
    """
    Extrae un atributo de un x509.Name por su OID.

    Args:
        name: Objeto x509.Name (Subject o Issuer).
        oid:  OID del atributo (ej: x509.NameOID.COMMON_NAME).

    Returns:
        Valor del atributo o '(no presente)' si no existe.
    """
    try:
        atributos = name.get_attributes_for_oid(oid)
        return atributos[0].value if atributos else "(no presente)"
    except Exception:
        return "(error al leer)"


def describir_clave_publica(clave_publica) -> str:
    """Retorna una descripción del tipo y tamaño de la clave pública."""
    if isinstance(clave_publica, rsa.RSAPublicKey):
        return f"RSA {clave_publica.key_size} bits"
    elif isinstance(clave_publica, ec.EllipticCurvePublicKey):
        return f"ECDSA {clave_publica.key_size} bits ({clave_publica.curve.name})"
    elif isinstance(clave_publica, dsa.DSAPublicKey):
        return f"DSA {clave_publica.key_size} bits"
    else:
        return type(clave_publica).__name__


def mostrar_certificado(cert: x509.Certificate, etiqueta: str = "Certificado") -> None:
    """
    Muestra los campos principales de un certificado X.509.

    Args:
        cert:    Objeto x509.Certificate a mostrar.
        etiqueta: Título descriptivo para la sección.
    """
    print(f"\n  ┌{'─'*60}┐")
    print(f"  │  {etiqueta:<58}│")
    print(f"  └{'─'*60}┘")

    # Subject (a quién pertenece el certificado)
    cn_subject  = extraer_atributo_name(cert.subject, x509.NameOID.COMMON_NAME)
    org_subject = extraer_atributo_name(cert.subject, x509.NameOID.ORGANIZATION_NAME)
    pais_sub    = extraer_atributo_name(cert.subject, x509.NameOID.COUNTRY_NAME)
    print(f"\n  SUBJECT (Titular del certificado):")
    print(f"    Common Name (CN)  : {cn_subject}")
    print(f"    Organization (O)  : {org_subject}")
    print(f"    Country (C)       : {pais_sub}")

    # Issuer (quién lo firmó)
    cn_issuer  = extraer_atributo_name(cert.issuer, x509.NameOID.COMMON_NAME)
    org_issuer = extraer_atributo_name(cert.issuer, x509.NameOID.ORGANIZATION_NAME)
    pais_iss   = extraer_atributo_name(cert.issuer, x509.NameOID.COUNTRY_NAME)
    print(f"\n  ISSUER (Autoridad Certificadora que lo firmó):")
    print(f"    Common Name (CN)  : {cn_issuer}")
    print(f"    Organization (O)  : {org_issuer}")
    print(f"    Country (C)       : {pais_iss}")

    # ¿Es auto-firmado? (Subject == Issuer → CA Raíz)
    es_autofirmado = cert.subject == cert.issuer
    tipo_cert = "🔑 CA RAÍZ (auto-firmado)" if es_autofirmado else "📄 Certificado firmado por CA"
    print(f"\n  Tipo              : {tipo_cert}")

    # Número de serie
    print(f"\n  NÚMERO DE SERIE:")
    serial_hex = format(cert.serial_number, 'X')
    # Formatear en bloques de 2 caracteres separados por ':'
    serial_formateado = ':'.join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
    print(f"    Decimal : {cert.serial_number}")
    print(f"    Hex     : {serial_formateado}")

    # Fechas de validez
    print(f"\n  FECHAS DE VALIDEZ:")
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after  = cert.not_valid_after_utc
    dias_restantes = (not_after - now).days
    estado_validez = f"✔ VÁLIDO ({dias_restantes} días restantes)" if dias_restantes > 0 else "✗ EXPIRADO"
    print(f"    Not Before (desde) : {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"    Not After  (hasta) : {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"    Estado             : {estado_validez}")

    # Clave pública
    print(f"\n  CLAVE PÚBLICA:")
    print(f"    Tipo y tamaño : {describir_clave_publica(cert.public_key())}")
    pub_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"    Tamaño DER    : {len(pub_der)} bytes")

    # Algoritmo de firma
    try:
        alg_firma = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "desconocido"
    except Exception:
        alg_firma = "desconocido"
    print(f"\n  ALGORITMO DE FIRMA : {alg_firma}")

    # Extensiones clave
    print(f"\n  EXTENSIONES RELEVANTES:")

    # Subject Alternative Names (SANs)
    try:
        ext_san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext_san.value.get_values_for_type(x509.DNSName)
        if sans:
            sans_mostrar = sans[:5]
            resto = f" ... (+{len(sans)-5} más)" if len(sans) > 5 else ""
            print(f"    SANs (DNS)     : {', '.join(sans_mostrar)}{resto}")
    except x509.ExtensionNotFound:
        print(f"    SANs           : (no presente)")

    # Basic Constraints (¿es CA?)
    try:
        ext_bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        es_ca = ext_bc.value.ca
        path_len = ext_bc.value.path_length
        print(f"    Basic Constr.  : CA={es_ca}, PathLen={path_len}")
    except x509.ExtensionNotFound:
        print(f"    Basic Constr.  : (no presente → certificado de entidad final)")

    # Key Usage
    try:
        ext_ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        usos = []
        ku = ext_ku.value
        if ku.digital_signature: usos.append("Digital Signature")
        if ku.key_cert_sign:     usos.append("Certificate Sign")
        if ku.crl_sign:          usos.append("CRL Sign")
        try:
            if ku.key_encipherment: usos.append("Key Encipherment")
        except Exception: pass
        print(f"    Key Usage      : {', '.join(usos) if usos else '(ninguno)'}")
    except x509.ExtensionNotFound:
        print(f"    Key Usage      : (no presente)")


def exportar_pem(cert_der: bytes, ruta_fichero: str) -> None:
    """
    Exporta un certificado en formato PEM a un fichero.

    Args:
        cert_der:      Certificado en formato DER (bytes).
        ruta_fichero:  Ruta del fichero PEM de salida.
    """
    cert_x509 = x509.load_der_x509_certificate(cert_der)
    pem_bytes = cert_x509.public_bytes(serialization.Encoding.PEM)

    with open(ruta_fichero, "wb") as f:
        f.write(pem_bytes)

    print(f"\n  ✔ Certificado exportado en PEM: '{ruta_fichero}' ({len(pem_bytes)} bytes)")

    # Mostrar las primeras líneas del PEM
    lineas_pem = pem_bytes.decode().splitlines()
    print(f"    {lineas_pem[0]}")
    print(f"    {lineas_pem[1][:50]}...")
    print(f"    ...")
    print(f"    {lineas_pem[-1]}")


def explicar_cadena_confianza() -> None:
    """Imprime una explicación detallada de la cadena de confianza PKI."""
    print("""
  ╔══════════════════════════════════════════════════════════════╗
  ║         CADENA DE CONFIANZA (Chain of Trust)                ║
  ╚══════════════════════════════════════════════════════════════╝

  ESTRUCTURA:
  ────────────────────────────────────────────────────────────────
  [Certificado RAÍZ]          Auto-firmado. Distribuido en el
   Root CA                    sistema operativo / navegador.
       │                      Ej: "DigiCert Global Root CA"
       │ firma
       ▼
  [Certificado INTERMEDIO]    Firmado por la CA raíz.
   Intermediate CA            El servidor lo envía junto al suyo.
       │                      Ej: "DigiCert TLS RSA SHA256 2020 CA1"
       │ firma
       ▼
  [Certificado SERVIDOR]      Firmado por el intermedio.
   Leaf / End-Entity          Contiene la clave pública del servidor.
                              Ej: CN=www.google.com

  PROCESO DE VALIDACIÓN (en el cliente HTTPS):
  ─────────────────────────────────────────────
  1. El servidor envía: [cert_servidor + cert_intermedio]
  2. El cliente verifica la firma del cert_servidor
     usando la clave pública del cert_intermedio.
  3. El cliente verifica la firma del cert_intermedio
     usando la clave pública de la CA raíz.
  4. Si la CA raíz está en el Root Store → CONFIANZA ESTABLECIDA.
  5. Si cualquier firma falla → ERROR de certificado (ej: NET::ERR_CERT_AUTHORITY_INVALID)

  ¿POR QUÉ USAR CA INTERMEDIAS?
  ───────────────────────────────
  • La clave privada de la CA raíz nunca se expone directamente.
    Las CA intermedias están en HSMs (Hardware Security Modules) en línea.
  • Si un intermedio se ve comprometido → se revoca SOLO ese intermedio.
    Sin intermedias, comprometer la raíz invalidaría TODO internet.
  • Permite delegar la emisión: una empresa puede operar su propia
    CA intermedia (subordinada) firmada por una raíz pública.

  REVOCACIÓN DE CERTIFICADOS:
  ────────────────────────────
  • CRL  (Certificate Revocation List): lista de certificados revocados.
  • OCSP (Online Certificate Status Protocol): consulta en tiempo real.
  • OCSP Stapling: el servidor adjunta la respuesta OCSP en el handshake.
    """)


if __name__ == "__main__":
    # Permitir pasar el host como argumento
    host = sys.argv[1] if len(sys.argv) > 1 else SITIO_DEFECTO

    print("=" * 65)
    print("  EJERCICIO 6 — Certificados X.509 y Cadena de Confianza")
    print("=" * 65)
    print(f"\n  Conectando a: https://{host}:{PUERTO_HTTPS}")
    print("─" * 65)

    try:
        # ── Obtener el certificado del servidor ──────────────────────────────
        print("\n[1] Estableciendo conexión TLS y obteniendo certificado...")

        # Intentamos primero con verificación completa (modo producción)
        cert_x509 = None
        cert_der  = None
        try:
            cert_x509, cert_der = obtener_cert_simple(host, PUERTO_HTTPS, verificar=True)
            print(f"    ✔ Conexión TLS verificada correctamente.")
        except ssl.SSLCertVerificationError:
            # En entornos de laboratorio con proxy interceptor, la cadena
            # de certificados puede estar "rota". Usamos modo sin verificación
            # para poder analizar el certificado igualmente.
            print("    ℹ  Verificación SSL estricta falló (posible proxy de red).")
            print("       Reintentando en modo laboratorio (sin verificación)...")
            cert_x509, cert_der = obtener_cert_simple(host, PUERTO_HTTPS, verificar=False)

        print(f"    ✔ Certificado obtenido ({len(cert_der)} bytes en DER).")

        # ── Mostrar información del certificado ──────────────────────────────
        print("\n[2] Análisis del certificado del servidor:")
        mostrar_certificado(cert_x509, f"Certificado del servidor: {host}")

        # ── Exportar en PEM ──────────────────────────────────────────────────
        print("\n[3] Exportando certificado en formato PEM:")
        exportar_pem(cert_der, FICHERO_PEM)

        # ── Intentar obtener la cadena completa ──────────────────────────────
        print("\n[4] Intentando obtener la cadena completa de certificados...")
        try:
            cadena = obtener_cadena_certificados(host, PUERTO_HTTPS)
            if cadena and len(cadena) > 1:
                print(f"    ✔ Cadena obtenida: {len(cadena)} certificado(s)")
                etiquetas = ["🌐 Servidor (Leaf)", "🔗 CA Intermedia", "🔑 CA Raíz"]
                for idx, (cert_c, _) in enumerate(cadena):
                    etiqueta = etiquetas[idx] if idx < len(etiquetas) else f"Certificado #{idx+1}"
                    mostrar_certificado(cert_c, etiqueta)
            else:
                print("    ℹ Solo se obtuvo el certificado del servidor.")
                print("      (La cadena completa requiere Python 3.10+ y soporte del servidor)")
        except Exception as e_cadena:
            print(f"    ℹ No se pudo obtener la cadena completa: {e_cadena}")
            print("      Mostrando solo el certificado del servidor.")

        # ── Explicación teórica ──────────────────────────────────────────────
        print("\n[5] Explicación de la cadena de confianza:")
        explicar_cadena_confianza()

        # ── Comandos OpenSSL equivalentes ────────────────────────────────────
        print("=" * 65)
        print("  COMANDOS OPENSSL EQUIVALENTES (para referencia)")
        print("=" * 65)
        print(f"""
  # Ver el certificado completo en texto:
  openssl x509 -in {FICHERO_PEM} -text -noout

  # Ver solo el subject e issuer:
  openssl x509 -in {FICHERO_PEM} -subject -issuer -noout

  # Ver las fechas de validez:
  openssl x509 -in {FICHERO_PEM} -dates -noout

  # Ver el número de serie:
  openssl x509 -in {FICHERO_PEM} -serial -noout

  # Obtener certificado directamente con OpenSSL:
  echo | openssl s_client -connect {host}:{PUERTO_HTTPS} -showcerts 2>/dev/null | \\
    openssl x509 -text -noout

  # Verificar la cadena de certificados:
  openssl s_client -connect {host}:{PUERTO_HTTPS} -showcerts 2>/dev/null
        """)

    except ssl.SSLCertVerificationError as e:
        print(f"\n  ✗ Error de verificación SSL: {e}")
        print("    El certificado del servidor no es válido o no es de confianza.")
    except socket.timeout:
        print(f"\n  ✗ Timeout: no se pudo conectar a {host}:{PUERTO_HTTPS}")
        print(f"    Verifica la conectividad de red.")
    except socket.gaierror as e:
        print(f"\n  ✗ Error DNS: no se pudo resolver '{host}': {e}")
        print(f"    Verifica el nombre del host.")
    except ConnectionRefusedError:
        print(f"\n  ✗ Conexión rechazada por {host}:{PUERTO_HTTPS}")
    except Exception as e:
        print(f"\n  ✗ Error inesperado: {type(e).__name__}: {e}")

    print("\n" + "=" * 65)
    print("  Proceso completado.")
    print("=" * 65)
