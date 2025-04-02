from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

app = Flask(__name__)

# Secure key derivation using PBKDF2 for AES
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000

# Encrypt data using AES-256 (GCM mode for security)
def encrypt_data(text, password):
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    encrypted_payload = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return encrypted_payload

# Decrypt data using AES-256
def decrypt_data(encrypted_text, password):
    try:
        data = base64.b64decode(encrypted_text)
        salt, nonce, tag, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+16], data[SALT_SIZE+16:SALT_SIZE+32], data[SALT_SIZE+32:]

        key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(ciphertext, tag).decode()

        return decrypted_text
    except Exception as e:
        return "Invalid Key or Data!"

# Encrypt data using RSA (Asymmetric encryption)
def rsa_encrypt(text, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_text = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted_text).decode()

# Decrypt data using RSA
def rsa_decrypt(encrypted_text, private_key):
    try:
        cipher = PKCS1_OAEP.new(private_key)
        encrypted_data = base64.b64decode(encrypted_text)
        decrypted_text = cipher.decrypt(encrypted_data).decode()
        return decrypted_text
    except Exception as e:
        return "Invalid Key or Data!"

# XOR Encryption
def xor_encrypt(text, xor_key):
    encrypted_text = ''.join(chr(ord(c) ^ xor_key) for c in text)
    return base64.b64encode(encrypted_text.encode()).decode()

# XOR Decryption (same as encryption, since XOR is symmetric)
def xor_decrypt(encrypted_text, xor_key):
    encrypted_data = base64.b64decode(encrypted_text).decode()
    decrypted_text = ''.join(chr(ord(c) ^ xor_key) for c in encrypted_data)
    return decrypted_text

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json['text']
    password = request.json['password']
    algorithm = request.json.get('algorithm', 'aes')  # Default to AES if no algorithm is specified

    if algorithm == 'aes':
        encrypted_text = encrypt_data(data, password)
    elif algorithm == 'rsa':
        # Generate RSA keys if needed
        key = RSA.generate(2048)
        public_key = key.publickey()
        encrypted_text = rsa_encrypt(data, public_key)
    elif algorithm == 'xor':
        xor_key = int(request.json['xor_key'])  # XOR key should be provided
        encrypted_text = xor_encrypt(data, xor_key)
    else:
        return jsonify({'error': 'Unknown algorithm'}), 400

    return jsonify({'encrypted_text': encrypted_text})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_text = request.json['text']
    password = request.json['password']
    algorithm = request.json.get('algorithm', 'aes')  # Default to AES if no algorithm is specified

    if algorithm == 'aes':
        decrypted_text = decrypt_data(encrypted_text, password)
    elif algorithm == 'rsa':
        # RSA private key should be provided for decryption
        private_key = RSA.import_key(password)  # Assuming 'password' is the private key
        decrypted_text = rsa_decrypt(encrypted_text, private_key)
    elif algorithm == 'xor':
        xor_key = int(request.json['xor_key'])  # XOR key should be provided
        decrypted_text = xor_decrypt(encrypted_text, xor_key)
    else:
        return jsonify({'error': 'Unknown algorithm'}), 400

    return jsonify({'decrypted_text': decrypted_text})

if __name__ == '__main__':
    app.run(debug=True)
