from flask import Flask, request, jsonify, render_template_string, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
import os
import base64
import logging
import secrets
import uuid

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
logging.basicConfig(level=logging.DEBUG)

# Create a 'secure_uploads' directory within the Flask app directory
UPLOAD_FOLDER = os.path.join(app.root_path, 'secure_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Ensure the upload folder permissions are restricted
os.chmod(UPLOAD_FOLDER, 0o700)  # Only the owner can read, write, and execute

# Create a .htaccess file to prevent direct access
with open(os.path.join(UPLOAD_FOLDER, '.htaccess'), 'w') as f:
    f.write('Deny from all')

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure File Upload</title>
    </head>
    <body>
        <h1>Secure File Upload</h1>
        <input type="file" id="fileInput">
        <button onclick="uploadFile()">Upload</button>
        <div id="status"></div>

        <script>
        async function uploadFile() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            if (!file) {
                alert('Please select a file');
                return;
            }

            try {
                const keyResponse = await fetch('/get_public_key');
                const { public_key } = await keyResponse.json();

                const fileContent = await file.arrayBuffer();
                
                const aesKey = await window.crypto.subtle.generateKey(
                    { name: "AES-GCM", length: 256 },
                    true,
                    ["encrypt", "decrypt"]
                );

                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const encryptedContent = await window.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv },
                    aesKey,
                    fileContent
                );

                const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

                const binaryDerString = window.atob(public_key);
                const binaryDer = new Uint8Array(binaryDerString.length);
                for (let i = 0; i < binaryDerString.length; i++) {
                    binaryDer[i] = binaryDerString.charCodeAt(i);
                }

                const importedPublicKey = await window.crypto.subtle.importKey(
                    "spki",
                    binaryDer,
                    {
                        name: "RSA-OAEP",
                        hash: "SHA-256"
                    },
                    true,
                    ["encrypt"]
                );

                const encryptedAesKey = await window.crypto.subtle.encrypt(
                    {
                        name: "RSA-OAEP"
                    },
                    importedPublicKey,
                    exportedAesKey
                );

                const formData = new FormData();
                formData.append('file', new Blob([encryptedContent]), file.name);
                formData.append('encryptedKey', new Blob([encryptedAesKey]));
                formData.append('iv', new Blob([iv]));

                const uploadResponse = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });

                const result = await uploadResponse.text();
                document.getElementById('status').textContent = result;
            } catch (error) {
                console.error('Error:', error);
                document.getElementById('status').textContent = 'Error: ' + error.message;
            }
        }
        </script>
    </body>
    </html>
    ''')

@app.route('/get_public_key')
def get_public_key():
    private_key, public_key = generate_key_pair()
    
    app.config[f'private_key_{request.remote_addr}'] = private_key
    
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({'public_key': base64.b64encode(public_key_der).decode('utf-8')})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or 'encryptedKey' not in request.files or 'iv' not in request.files:
        return 'Missing required data', 400
    
    file = request.files['file']
    encrypted_key = request.files['encryptedKey'].read()
    iv = request.files['iv'].read()

    if file.filename == '':
        return 'No selected file', 400
    
    private_key = app.config.get(f'private_key_{request.remote_addr}')
    if not private_key:
        return 'No private key found', 400
    
    try:
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_content = file.read()
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(encrypted_content[:-16]) + decryptor.finalize_with_tag(encrypted_content[-16:])

        # Generate a secure random filename
        secure_filename = str(uuid.uuid4())
        filename = os.path.join(UPLOAD_FOLDER, secure_filename)
        with open(filename, 'wb') as f:
            f.write(decrypted_content)
        
        # Set restrictive permissions on the file
        os.chmod(filename, 0o600)  # Only the owner can read and write
        
        del app.config[f'private_key_{request.remote_addr}']
        
        return 'File uploaded and securely stored', 200
    except Exception as e:
        return f'Error during file upload: {str(e)}', 500

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, ssl_context=('server.crt', 'server.key'))