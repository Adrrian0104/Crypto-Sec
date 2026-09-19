import base64
import io
import os
import struct
import mimetypes

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

        # ETAPA 1 del descifrado: RSA recupera la clave AES original
        aes_key = private_key.decrypt(base64.b64decode(encrypted_key_b64), RSA_OAEP)

        # ETAPA 2 del descifrado: AES-GCM descifra el contenido con esa clave
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

        return jsonify({
            "decrypted_message": plaintext.decode("utf-8"),
            "aes_key_debug": base64.b64encode(aes_key).decode("utf-8"),
        })
    except Exception:
        # No revelamos si falló la clave RSA o el tag de autenticación de AES:
        # esa distinción es información sensible para un atacante.
        return jsonify({"error": "No se pudo descifrar. Verifica la clave privada y el paquete cifrado."}), 400


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

        data = uploaded_file.read()
        if len(data) < 15:
            return jsonify({"error": "El archivo cifrado está corrupto o incompleto."}), 400

        key_len = struct.unpack(">H", data[0:2])[0]
        offset = 2
        encrypted_key = data[offset:offset + key_len]
        offset += key_len

        ext_len = data[offset]
        offset += 1
        ext = data[offset:offset + ext_len].decode("utf-8")
        offset += ext_len

        nonce = data[offset:offset + 12]
        ciphertext = data[offset + 12:]

        aes_key = private_key.decrypt(encrypted_key, RSA_OAEP)
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

        mimetype = mimetypes.guess_type("archivo" + ext)[0] or "application/octet-stream"
        buffer = io.BytesIO(plaintext)
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype=mimetype,
            as_attachment=False,
            download_name="descifrado" + ext,
        )
    except Exception:
        return jsonify({"error": "No se pudo descifrar. Verifica la clave privada y el archivo."}), 400


if __name__ == "__main__":
    app.run(debug=True, port=5000)