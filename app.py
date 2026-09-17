import base64
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    # Generar par de claves RSA de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Exportar clave privada a formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Exportar clave pública a formato PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return jsonify({
        "private_key": private_pem,
        "public_key": public_pem
    })

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    message = data.get("message", "").encode("utf-8")
    public_key_pem = data.get("public_key", "")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        
        # Cifrar usando RSA con relleno OAEP + SHA256
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Codificar en Base64 para enviarlo de forma legible al frontend
        ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
        return jsonify({"ciphertext": ciphertext_b64})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    ciphertext_b64 = data.get("ciphertext", "")
    private_key_pem = data.get("private_key", "")

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        ciphertext = base64.b64decode(ciphertext_b64)

        # Descifrar usando RSA
        decrypted_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return jsonify({"decrypted_message": decrypted_bytes.decode("utf-8")})
    except Exception as e:
        return jsonify({"error": "Error al descifrar. Verifica la clave privada o el mensaje."}), 400

if __name__ == "__main__":
    app.run(debug=True, port=5000)