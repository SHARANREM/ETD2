from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

app = Flask(__name__)
# Generate RSA keys once and reuse them
rsa_key = RSA.generate(2048)
private_key = rsa_key
public_key = rsa_key.publickey()

# Secure key derivation using PBKDF2 for AES
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000

# Encrypt data using AES-256 (GCM mode for security)
def encrypt_data(text, passphrase):
    if len(passphrase) < 24:
        return "Passphrase must be at least 24 characters long."

    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(passphrase, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    encrypted_payload = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return encrypted_payload

# Decrypt data using AES-256
def decrypt_data(encrypted_text, passphrase):
    if len(passphrase) < 24:
        return "Passphrase must be at least 24 characters long."

    try:
        data = base64.b64decode(encrypted_text)
        salt, nonce, tag, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+16], data[SALT_SIZE+16:SALT_SIZE+32], data[SALT_SIZE+32:]

        key = PBKDF2(passphrase, salt, dkLen=KEY_SIZE, count=ITERATIONS)
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

# Caesar Cipher
def caesar_encrypt(text, shift=3):
    encrypted = ''.join(chr((ord(char) + shift) % 256) for char in text)
    return base64.b64encode(encrypted.encode()).decode()

def caesar_decrypt(text, shift=3):
    decrypted = base64.b64decode(text).decode()
    return ''.join(chr((ord(char) - shift) % 256) for char in decrypted)

# Base64 Encode/Decode
def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def base64_decrypt(text):
    return base64.b64decode(text).decode()

# Reverse Cipher
def reverse_encrypt(text):
    return text[::-1]

def reverse_decrypt(text):
    return text[::-1]

# Vigenère Cipher
def vigenere_encrypt(text, key):
    key = (key * (len(text) // len(key) + 1))[:len(text)]
    encrypted = ''.join(chr((ord(c) + ord(k)) % 256) for c, k in zip(text, key))
    return base64.b64encode(encrypted.encode()).decode()

def vigenere_decrypt(text, key):
    decoded = base64.b64decode(text).decode()
    key = (key * (len(decoded) // len(key) + 1))[:len(decoded)]
    decrypted = ''.join(chr((ord(c) - ord(k)) % 256) for c, k in zip(decoded, key))
    return decrypted

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json['text']
    passphrase = request.json['password']
    xor_key = int(request.json.get('xor_key', 0))
    algorithms = request.json.get('algorithms', [])

    # Check passphrase length if AES or Vigenère is selected
    if ('aes' in algorithms or 'vigenere' in algorithms) and len(passphrase) < 24:
        return jsonify({'error': 'Passphrase must be at least 24 characters long.'}), 400

    encrypted = data
    for algo in algorithms:
        if algo == 'aes':
            encrypted = encrypt_data(encrypted, passphrase)
        elif algo == 'rsa':
            encrypted = rsa_encrypt(encrypted, public_key)
        elif algo == 'xor':
            encrypted = xor_encrypt(encrypted, xor_key)
        elif algo == 'caesar':
            encrypted = caesar_encrypt(encrypted)
        elif algo == 'base64':
            encrypted = base64_encrypt(encrypted)
        elif algo == 'reverse':
            encrypted = reverse_encrypt(encrypted)
        elif algo == 'vigenere':
            encrypted = vigenere_encrypt(encrypted, passphrase)
        else:
            return jsonify({'error': 'Unknown algorithm'}), 400

    return jsonify({'encrypted_text': encrypted})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted = request.json['text']
    passphrase = request.json['password']
    xor_key = int(request.json.get('xor_key', 0))
    algorithms = request.json.get('algorithms', [])

    # Check passphrase length if AES or Vigenère is selected
    if ('aes' in algorithms or 'vigenere' in algorithms) and len(passphrase) < 24:
        return jsonify({'error': 'Passphrase must be at least 24 characters long.'}), 400

    decrypted = encrypted
    for algo in reversed(algorithms):
        if algo == 'aes':
            decrypted = decrypt_data(decrypted, passphrase)
        elif algo == 'rsa':
            decrypted = rsa_decrypt(decrypted, private_key)
        elif algo == 'xor':
            decrypted = xor_decrypt(decrypted, xor_key)
        elif algo == 'caesar':
            decrypted = caesar_decrypt(decrypted)
        elif algo == 'base64':
            decrypted = base64_decrypt(decrypted)
        elif algo == 'reverse':
            decrypted = reverse_decrypt(decrypted)
        elif algo == 'vigenere':
            decrypted = vigenere_decrypt(decrypted, passphrase)
        else:
            return jsonify({'error': 'Unknown algorithm'}), 400

    return jsonify({'decrypted_text': decrypted})

if __name__ == '__main__':
    app.run(debug=True)
