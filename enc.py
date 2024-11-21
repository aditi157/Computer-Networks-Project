from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import sqlite3

# Database setup
def init_db():
    conn = sqlite3.connect('file_keys.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS FileKey (id INTEGER PRIMARY KEY, filename TEXT UNIQUE NOT NULL, key TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def save_file_key(filename, private_key_base64):
    conn = sqlite3.connect('file_keys.db')
    c = conn.cursor()
    c.execute('INSERT INTO FileKey (filename, key) VALUES (?, ?)', (filename, private_key_base64))
    conn.commit()
    conn.close()

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_file(file_path):
    private_key, public_key = generate_keys()
    
    # Generate a random AES key and IV
    aes_key = os.urandom(32)  # AES key for AES-256
    iv = os.urandom(16)  # IV for CFB mode

    # Encrypt the file data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Encrypt the AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted file with IV and encrypted AES key
    encrypted_file_path = f'encrypted/{os.path.basename(file_path)}.enc'
    os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
    with open(encrypted_file_path, 'wb') as ef:
        ef.write(iv)  # Write the IV
        ef.write(encrypted_aes_key)  # Write the encrypted AES key
        
        # Encrypt the file data using AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        ef.write(encrypted_data)

    # Save the private key as base64
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_base64 = base64.b64encode(private_key_bytes).decode('utf-8')

    save_file_key(os.path.basename(file_path), private_key_base64)

    return encrypted_file_path, private_key_base64

if __name__ == "__main__":
    init_db()
    file_path = input("Enter the path of the file to encrypt: ")
    encrypted_file_path, private_key = encrypt_file(file_path)
    print(f"File encrypted: {encrypted_file_path}")
    print(f"Private Key (Base64): {private_key}")
