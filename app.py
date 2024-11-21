from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_keys.db'
app.secret_key = 'my_secret_key'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class FileKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), unique=True, nullable=False)
    key = db.Column(db.String(120), nullable=False)

# home
@app.route('/')
def home():
    return render_template('home.html')

# register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('ftp_server'))
        return 'Invalid credentials'
    return render_template('login.html')

# ftp
@app.route('/ftp_server')
def ftp_server():
    return render_template('ftp_server.html', ftp_server_url='ftp://172.24.144.1/')

# decrypt file
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_file():
    if request.method == 'POST':
        filename = request.form['filename']
        key = request.form['key']
        folder_path = request.form['folder_path']

        folder_path = os.path.abspath(folder_path)
        encrypted_file_path = os.path.join(folder_path, f'{filename}.enc')

        if not os.path.exists(encrypted_file_path):
            return f'Encrypted file not found at: {encrypted_file_path}'

        try:
            #decode base64
            private_key_bytes = base64.b64decode(key)
            private_key = serialization.load_pem_private_key(private_key_bytes, password=None)

            
            with open(encrypted_file_path, 'rb') as ef:
                iv = ef.read(16) 
                encrypted_aes_key = ef.read(256)  

               
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                
                decrypted_file_path = f'decrypted_files/{filename}'
                os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)

                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                with open(decrypted_file_path, 'wb') as df:
                    while True:
                        encrypted_chunk = ef.read(2048)  
                        if not encrypted_chunk:
                            break
                        decrypted_chunk = decryptor.update(encrypted_chunk)
                        df.write(decrypted_chunk)
                    df.write(decryptor.finalize())  

            return send_file(decrypted_file_path, as_attachment=True)

        except Exception as e:
            print(f"Error details: {e}") 
            return f'Decryption failed: {str(e)}'

    return render_template('decrypt.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True, host='0.0.0.0', port=5000)   
