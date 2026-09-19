import base64
import io
import os
import struct
import mimetypes
import secrets
import string

from flask import Flask, render_template, request, jsonify, send_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

RSA_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


# ============================================================
#  RESULTADO ALTERNATIVO (descifrado no válido)
# ============================================================
#  AES-GCM ya es un cifrado AUTENTICADO: si la clave AES es incorrecta,
#  o si el criptograma fue modificado, `AESGCM.decrypt()` lanza una
#  excepción (falla la verificación del tag de autenticación) en vez de
#  devolver datos incorrectos silenciosamente. Lo mismo ocurre si RSA
#  no logra recuperar la clave AES original con la clave privada dada.
#  Estas dos funciones generan el contenido de "fallback" que se
#  muestra en ese caso: nunca es el contenido original, es distinto en
#  cada intento, y no revela ninguna información sobre la clave
#  correcta ni sobre el contenido cifrado.

def _generate_fallback_text() -> str:
    """Texto aleatorio, legible y distinto en cada llamada, usado como
    resultado visual cuando el descifrado no es válido. Se genera con
    `secrets`, el generador de aleatoriedad criptográficamente seguro
    de la librería estándar de Python (no `random`)."""
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    length = secrets.choice(range(16, 25))
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _generate_fallback_image_svg() -> bytes:
    """Imagen SVG abstracta, distinta en cada llamada, usada como
    resultado visual cuando el descifrado de una imagen no es válido.
    No contiene ningún dato derivado de la imagen original: son solo
    formas geométricas y colores aleatorios, coherentes con la
    paleta/estética tecnológica de CryptoSec (cian/violeta sobre fondo
    oscuro)."""
    palette = ["#22d3ee", "#818cf8", "#a78bfa", "#22c55e", "#fbbf24", "#f87171"]
    size = 480
    shapes = []
    for _ in range(secrets.choice(range(9, 15))):
        kind = secrets.choice(["circle", "rect", "line"])
        color = secrets.choice(palette)
        opacity = round(0.15 + secrets.randbelow(55) / 100, 2)
        if kind == "circle":
            cx, cy = secrets.randbelow(size), secrets.randbelow(size)
            r = 10 + secrets.randbelow(70)
            shapes.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" fill-opacity="{opacity}" />'
            )
        elif kind == "rect":
            x, y = secrets.randbelow(size), secrets.randbelow(size)
            w, h = 12 + secrets.randbelow(120), 12 + secrets.randbelow(120)
            rot = secrets.randbelow(360)
            shapes.append(
                f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{color}" '
                f'fill-opacity="{opacity}" transform="rotate({rot} {x} {y})" />'
            )
        else:
            x1, y1 = secrets.randbelow(size), secrets.randbelow(size)
            x2, y2 = secrets.randbelow(size), secrets.randbelow(size)
            shapes.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
                f'stroke-width="{1 + secrets.randbelow(3)}" stroke-opacity="{opacity}" />'
            )

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'width="{size}" height="{size}">'
        '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0%" stop-color="#05070f"/>'
        '<stop offset="100%" stop-color="#0b0f24"/>'
        "</linearGradient></defs>"
        f'<rect width="{size}" height="{size}" fill="url(#bg)"/>'
        f"{''.join(shapes)}"
        '<g font-family="monospace" font-size="13" fill="#8b96ac">'
        f'<text x="16" y="{size - 16}">DESCIFRADO NO VÁLIDO</text>'
        "</g></svg>"
    )
    return svg.encode("utf-8")


@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
#  GENERACIÓN DE CLAVES RSA (par de claves del usuario)
# ============================================================
#  RSA solo se usa aquí para proteger la clave AES, nunca para
#  cifrar directamente el contenido (texto/imagen). Por eso una
#  clave RSA de 2048 bits es más que suficiente: solo cifra
#  32 bytes (la clave AES-256), nunca datos de tamaño arbitrario.

@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return jsonify({"private_key": private_pem, "public_key": public_pem})


# ============================================================
#  CIFRADO HÍBRIDO — TEXTO
# ============================================================
#
#  Paquete de texto (string para copiar/pegar):
#     encrypted_key_b64 . nonce_b64 . ciphertext_b64
#
#  - encrypted_key: la clave AES-256 (32 bytes), cifrada con la
#    clave PÚBLICA RSA del destinatario (RSA-OAEP/SHA256).
#  - nonce: 12 bytes aleatorios usados una sola vez con esa clave AES.
#  - ciphertext: el texto cifrado con AES-256-GCM (incluye el tag
#    de autenticación al final, agregado por la propia librería).

@app.route("/hybrid/encrypt-text", methods=["POST"])
def hybrid_encrypt_text():
    data = request.get_json()
    message = data.get("message", "")
    public_key_pem = data.get("public_key", "")

    if not message:
        return jsonify({"error": "El mensaje está vacío."}), 400
    if not public_key_pem:
        return jsonify({"error": "Falta la clave pública RSA del destinatario."}), 400

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        # ETAPA 2: generación de clave AES-256 aleatoria (una por cada cifrado)
        aes_key = AESGCM.generate_key(bit_length=256)

        # ETAPA 3: cifrado del contenido con AES-GCM
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, message.encode("utf-8"), None)

        # ETAPA 4: la clave AES se protege cifrándola con RSA (no el contenido)
        encrypted_key = public_key.encrypt(aes_key, RSA_OAEP)

        return jsonify({
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            # Solo para la animación didáctica: la clave AES en claro NUNCA
            # debería exponerse en un sistema real una vez protegida por RSA.
            "aes_key_debug": base64.b64encode(aes_key).decode("utf-8"),
        })
    except Exception as e:
        return jsonify({"error": f"No se pudo cifrar: {str(e)}"}), 400


@app.route("/hybrid/decrypt-text", methods=["POST"])
def hybrid_decrypt_text():
    data = request.get_json()
    encrypted_key_b64 = data.get("encrypted_key", "")
    nonce_b64 = data.get("nonce", "")
    ciphertext_b64 = data.get("ciphertext", "")
    private_key_pem = data.get("private_key", "")

    if not (encrypted_key_b64 and nonce_b64 and ciphertext_b64):
        return jsonify({"error": "El paquete cifrado está incompleto."}), 400
    if not private_key_pem:
        return jsonify({"error": "Falta tu clave privada RSA."}), 400

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
    except Exception:
        # Esto es un error de formato de entrada (no un PEM válido), distinto
        # de "clave incorrecta": se sigue tratando como 400 normal.
        return jsonify({"error": "La clave privada RSA no tiene un formato válido."}), 400

    # A partir de aquí cualquier fallo -- RSA no recupera la clave AES
    # correcta, o AES-GCM rechaza el tag de autenticación porque la clave
    # es incorrecta o el paquete fue alterado -- se trata de forma
    # unificada como "descifrado NO VÁLIDO". No se distingue la causa
    # exacta (evita filtrar información útil a un atacante) y, sobre todo,
    # NUNCA se devuelve el contenido original en este caso: en su lugar se
    # genera un texto aleatorio de demostración, distinto en cada intento.
    try:
        # ETAPA 1 del descifrado: RSA recupera la clave AES original
        aes_key = private_key.decrypt(base64.b64decode(encrypted_key_b64), RSA_OAEP)

        # ETAPA 2 del descifrado: AES-GCM descifra y AUTENTICA el contenido
        # con esa clave (si la clave o el ciphertext no coinciden, lanza
        # excepción en vez de devolver bytes incorrectos)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        message = plaintext.decode("utf-8")

        # ETAPA 3: condición explícita VÁLIDO antes de exponer el contenido
        return jsonify({
            "valid": True,
            "decrypted_message": message,
            "aes_key_debug": base64.b64encode(aes_key).decode("utf-8"),
        })
    except Exception:
        # Condición NO VÁLIDO: no hay clave AES real que mostrar ni
        # contenido original que exponer. Se genera un resultado de
        # demostración en su lugar.
        return jsonify({
            "valid": False,
            "decrypted_message": _generate_fallback_text(),
            "notice": "La clave proporcionada no permite recuperar el contenido original.",
        })


# ============================================================
#  CIFRADO HÍBRIDO — ARCHIVOS (IMÁGENES)
# ============================================================
#
#  Formato binario del archivo .hyb:
#    [2 bytes]  longitud de la clave AES cifrada con RSA (big-endian)
#    [N bytes]  clave AES cifrada con RSA-OAEP
#    [1 byte]   longitud de la extensión original (ej. ".png" -> 4)
#    [M bytes]  extensión original
#    [12 bytes] nonce de AES-GCM
#    [resto]    contenido cifrado con AES-GCM (incluye tag)

@app.route("/hybrid/encrypt-file", methods=["POST"])
def hybrid_encrypt_file():
    uploaded_file = request.files.get("file")
    public_key_pem = request.form.get("public_key", "")

    if uploaded_file is None:
        return jsonify({"error": "No se recibió ningún archivo."}), 400
    if not public_key_pem:
        return jsonify({"error": "Falta la clave pública RSA del destinatario."}), 400

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        original_bytes = uploaded_file.read()
        if not original_bytes:
            return jsonify({"error": "El archivo está vacío."}), 400
        ext = os.path.splitext(uploaded_file.filename)[1] or ""
        ext_bytes = ext.encode("utf-8")

        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, original_bytes, None)
        encrypted_key = public_key.encrypt(aes_key, RSA_OAEP)

        payload = (
            struct.pack(">H", len(encrypted_key)) + encrypted_key +
            bytes([len(ext_bytes)]) + ext_bytes +
            nonce + ciphertext
        )

        buffer = io.BytesIO(payload)
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=(uploaded_file.filename or "archivo") + ".hyb",
        )
    except Exception as e:
        return jsonify({"error": f"No se pudo cifrar el archivo: {str(e)}"}), 400


@app.route("/hybrid/decrypt-file", methods=["POST"])
def hybrid_decrypt_file():
    uploaded_file = request.files.get("file")
    private_key_pem = request.form.get("private_key", "")

    if uploaded_file is None:
        return jsonify({"error": "No se recibió ningún archivo."}), 400
    if not private_key_pem:
        return jsonify({"error": "Falta tu clave privada RSA."}), 400

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
    except Exception:
        return jsonify({"error": "La clave privada RSA no tiene un formato válido."}), 400

    data = uploaded_file.read()
    if not data:
        return jsonify({"error": "El archivo está vacío."}), 400

    # A partir de aquí cualquier fallo -- estructura corrupta/incompleta,
    # clave RSA incorrecta, o tag de autenticación AES-GCM inválido (clave
    # incorrecta o archivo alterado) -- se trata como "descifrado NO
    # VÁLIDO" y responde con una imagen de demostración generada al azar,
    # nunca con la imagen original ni con un error críptico del navegador.
    try:
        if len(data) < 15:
            raise ValueError("archivo demasiado corto para ser un paquete .hyb válido")

        key_len = struct.unpack(">H", data[0:2])[0]
        offset = 2
        encrypted_key = data[offset:offset + key_len]
        offset += key_len
        if len(encrypted_key) != key_len:
            raise ValueError("clave AES cifrada incompleta")

        ext_len = data[offset]
        offset += 1
        ext = data[offset:offset + ext_len].decode("utf-8")
        offset += ext_len

        nonce = data[offset:offset + 12]
        ciphertext = data[offset + 12:]
        if len(nonce) != 12 or not ciphertext:
            raise ValueError("payload cifrado incompleto")

        # ETAPA 1: RSA recupera la clave AES original
        aes_key = private_key.decrypt(encrypted_key, RSA_OAEP)
        # ETAPA 2: AES-GCM descifra y AUTENTICA el contenido
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

        # Condición explícita VÁLIDO antes de exponer el contenido original
        mimetype = mimetypes.guess_type("archivo" + ext)[0] or "application/octet-stream"
        buffer = io.BytesIO(plaintext)
        buffer.seek(0)
        response = send_file(
            buffer,
            mimetype=mimetype,
            as_attachment=False,
            download_name="descifrado" + ext,
        )
        response.headers["X-Decryption-Valid"] = "true"
        return response
    except Exception:
        # Condición NO VÁLIDO: no hay imagen original que mostrar. Se
        # genera una imagen de demostración (SVG abstracto) en su lugar,
        # distinta en cada intento, señalizada mediante una cabecera
        # dedicada para que el frontend la distinga de un descifrado real.
        svg_bytes = _generate_fallback_image_svg()
        buffer = io.BytesIO(svg_bytes)
        buffer.seek(0)
        response = send_file(
            buffer,
            mimetype="image/svg+xml",
            as_attachment=False,
            download_name="resultado_no_valido.svg",
        )
        response.headers["X-Decryption-Valid"] = "false"
        return response


if __name__ == "__main__":
    app.run(debug=True, port=5000)