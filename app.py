import os
import secrets
from flask import Flask, request, render_template, redirect, url_for, send_file, flash
from werkzeug.utils import secure_filename
from PIL import Image
from cryptography.fernet import Fernet
import sqlite3

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

UPLOAD_FOLDER = 'uploads/temp'
STEGO_FOLDER = 'uploads/stego'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STEGO_FOLDER, exist_ok=True)
DATABASE = 'resources.db'

# Initialize SQLite DB
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS resources
                 (id TEXT PRIMARY KEY, filename TEXT, token TEXT, key TEXT)''')
    conn.commit()
    conn.close()
init_db()

# --- Helpers ---
def file_to_bytes(path):
    with open(path, 'rb') as f:
        return f.read()

def bytes_to_file(data, path):
    with open(path, 'wb') as f:
        f.write(data)

def encrypt_bytes(data):
    key = Fernet.generate_key()
    f = Fernet(key)
    return f.encrypt(data), key

def decrypt_bytes(data, key):
    f = Fernet(key)
    return f.decrypt(data)

def hide_data_in_image(img_path, data_bytes):
    img = Image.open(img_path)
    max_bytes = (img.width * img.height * 3) // 8
    if len(data_bytes) > max_bytes:
        raise ValueError(f"Secret too large! Max: {max_bytes} bytes, got {len(data_bytes)} bytes")
    bin_data = ''.join(format(byte, '08b') for byte in data_bytes)
    pixels = list(img.getdata())
    new_pixels = []
    data_index = 0
    for pixel in pixels:
        r, g, b = pixel[:3]
        if data_index < len(bin_data): r = (r & ~1) | int(bin_data[data_index]); data_index+=1
        if data_index < len(bin_data): g = (g & ~1) | int(bin_data[data_index]); data_index+=1
        if data_index < len(bin_data): b = (b & ~1) | int(bin_data[data_index]); data_index+=1
        new_pixels.append((r,g,b))
    img.putdata(new_pixels)
    path = os.path.join(STEGO_FOLDER, f"stego_{secrets.token_hex(4)}.png")
    img.save(path)
    return path

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        secret_file = request.files['secret_file']
        cover_image = request.files['cover_image']
        if not secret_file or not cover_image:
            flash("Upload both secret file and cover image")
            return redirect(request.url)
        secret_path = os.path.join(UPLOAD_FOLDER, secure_filename(secret_file.filename))
        secret_file.save(secret_path)
        cover_path = os.path.join(UPLOAD_FOLDER, secure_filename(cover_image.filename))
        cover_image.save(cover_path)

        secret_bytes = file_to_bytes(secret_path)
        encrypted_bytes, key = encrypt_bytes(secret_bytes)
        try:
            stego_path = hide_data_in_image(cover_path, encrypted_bytes)
        except ValueError as e:
            flash(str(e))
            return redirect(request.url)

        resource_id = secrets.token_urlsafe(6)
        token = secrets.token_urlsafe(8)

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO resources VALUES (?,?,?,?)",
                  (resource_id, secret_file.filename, token, key.decode()))
        conn.commit()
        conn.close()

        link = url_for('access', resource_id=resource_id, _external=True)
        return render_template('link.html', link=link, token=token)
    return render_template('index.html')

@app.route('/access/<resource_id>', methods=['GET', 'POST'])
def access(resource_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT filename, token, key FROM resources WHERE id=?", (resource_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return "Resource not found!"
    filename, token_db, key = row
    if request.method == 'POST':
        token_input = request.form.get('token')
        if token_input != token_db:
            flash("Invalid token!")
            return redirect(request.url)
        stego_file = [f for f in os.listdir(STEGO_FOLDER) if f.startswith("stego_")][0]
        stego_path = os.path.join(STEGO_FOLDER, stego_file)
        encrypted_bytes = file_to_bytes(stego_path)
        decrypted_bytes = decrypt_bytes(encrypted_bytes, key.encode())
        output_path = os.path.join(UPLOAD_FOLDER, filename)
        bytes_to_file(decrypted_bytes, output_path)
        return send_file(output_path, as_attachment=True)
    return render_template('access.html', resource_id=resource_id)
    
if __name__ == '__main__':
    app.run(debug=True)
