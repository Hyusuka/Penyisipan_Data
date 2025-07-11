from flask import Flask, Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_file, current_app, send_from_directory, session
import os
import mysql.connector
import cv2
import numpy as np
import logging
import shutil
import re
import time
import hashlib
from io import BytesIO
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from datetime import datetime
from app.utils.database import db_manager
from pathlib import Path
from cryptography.fernet import Fernet
from typing import Optional, Tuple
from email.message import EmailMessage
from app.utils.send_email import send_email
from marshmallow import Schema, fields, ValidationError
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import Any, Optional
from app.utils.stego import LSBSteganography


main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class DecryptSchema(Schema):
    data = fields.String(required=True)

ALLOWED_EXTENSIONS = {'png'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_storage():
    """Validasi ruang penyimpanan tersedia"""
    _, _, free = shutil.disk_usage("/")
    return free >= 1024 * 1024  # Minimal 1MB

def configure_routes(app):
    app.register_blueprint(main)

def get_mysql_connection():
    return mysql.connector.connect(
        host=os.getenv('MYSQL_HOST', 'localhost'),
        user=os.getenv('MYSQL_USER', 'root'),
        password=os.getenv('MYSQL_PASSWORD', ''),
        database=os.getenv('MYSQL_DATABASE', 'kripto_stego')
    )

def verify_admin(username: str, password: str) -> bool:
    """Verifikasi kredensial admin dengan tipe yang aman"""
    try:
        with db_manager.get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(
                    "SELECT password_hash FROM admin_users WHERE username = %s", 
                    (username,)
                )
                admin = cursor.fetchone()
                
                if admin and check_password_hash(admin['password_hash'], password):
                    return True
        return False
    except Exception as e:
        logger.error(f"Error verifying admin: {str(e)}")
        return False

def log_proses(file_name: Optional[str], status: str, tipe: str = "encrypt") -> None:
    """Mencatat log proses ke database dengan penanganan file_name yang optional"""
    try:
        # Handle None case
        log_file_name = file_name if file_name is not None else "unknown"
        
        with db_manager.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO log_proses (tipe, nama_file, waktu, status)
                    VALUES (%s, %s, NOW(), %s)
                """, (tipe, log_file_name, status))
                conn.commit()
    except Exception as e:
        logger.error(f"Gagal mencatat log proses: {str(e)}")


def cleanup_folder(folder: str):
    if not os.path.isdir(folder):
        return
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")

def extract_data_from_image_cv2(image_path) -> bytes:
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("Gagal membaca gambar.")

    flat_image = image.flatten()
    bits = [str(int(pixel) & 1) for pixel in flat_image]

    length_bits = bits[:32]
    length = int(''.join(length_bits), 2)

    data_bits = bits[32:32 + length * 8]
    if len(data_bits) < length * 8:
        raise ValueError("Data tidak lengkap atau korup.")

    bytes_data = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = data_bits[i:i+8]
        bytes_data.append(int(''.join(byte), 2))

    return bytes(bytes_data)

def decrypt_data(encrypted_data: bytes, key: str) -> str:
    """Fungsi dekripsi yang sudah diperbaiki"""
    try:
        key_bytes = hashlib.sha256(key.encode()).digest()
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        if len(ciphertext) % 16 != 0:
            # Tambahkan padding manual jika diperlukan
            pad_len = 16 - (len(ciphertext) % 16)
            ciphertext += bytes([pad_len] * pad_len)
            
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise ValueError(f"Gagal proses dekripsi: {str(e)}")

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/juan/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Ambil nilai dengan sanitasi input
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Hard-coded credentials (hanya untuk development)
        HARDCODED_USERNAME = 'burung'
        HARDCODED_PASSWORD = '@Lovebird123'
        
        # Validasi input
        if not username or not password:
            flash('Username dan password harus diisi', 'error')
            return render_template('juan/login.html')
        
        # Verifikasi credentials
        if username == HARDCODED_USERNAME and password == HARDCODED_PASSWORD:
            session['admin_logged_in'] = True
            session.permanent = True  # Session tetap aktif sampai browser ditutup
            return redirect(url_for('main.admin'))
        
        # Jika verifikasi gagal
        flash('Username atau password salah', 'error')
    
    return render_template('juan/login.html')

@main.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Anda telah logout', 'success')
    return redirect(url_for('main.login'))

@main.route('/download-file/<filename>', endpoint='download_file')
def download_file(filename):
    try:
        # Dapatkan path absolut folder upload
        uploads_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
        
        # Validasi dan bersihkan nama file
        safe_filename = secure_filename(filename)
        if not safe_filename:
            raise ValueError("Nama file tidak valid")
            
        file_path = os.path.join(uploads_folder, safe_filename)
        
        # Log proses
        logger.info(f"Mencoba mengunduh: {file_path}")
        
        # Validasi eksistensi file
        if not os.path.isfile(file_path):
            logger.error(f"File tidak ditemukan: {file_path}")
            return jsonify({"error": "File tidak ditemukan"}), 404
            
        # Set header cache control
        response = send_from_directory(
            uploads_folder,
            safe_filename,
            as_attachment=True,
            download_name=safe_filename
        )

        response.headers['Cache-Control'] = 'no-store, must-revalidate'
        return response

    except Exception as e:
        logger.error(f"Kesalahan unduh: {str(e)}", exc_info=True)
        return jsonify({"error": "Gagal mengunduh file"}), 500

@main.route('/encrypt', methods=['GET', 'POST'])
def encrypt_route():
    if request.method == 'POST':
        # Deklarasi variabel di awal fungsi
        image_file = None
        image_filename = "unknown"
        
        try:
            start_time = datetime.now()
            start = time.time()

            # Ambil input dari form
            text = request.form.get("input_text", "").strip()
            password = request.form.get("key", "").strip()
            image_file = request.files.get("image")  # Inisialisasi di sini

            # Set filename awal
            image_filename = image_file.filename if (image_file and image_file.filename) else "unknown"

            # Validasi input
            if not image_file:
                log_proses(None, "Gagal: Gambar tidak boleh kosong", "encrypt")
                return jsonify({'status': 'error', 'message': 'Gambar tidak boleh kosong'}), 400
            
            if not text or not password:
                log_proses(image_filename, "Gagal: Pesan dan password harus diisi", "encrypt")
                return jsonify({'status': 'error', 'message': 'Pesan dan password harus diisi'}), 400

            # Baca gambar
            in_memory_file = image_file.read()
            img = cv2.imdecode(np.frombuffer(in_memory_file, np.uint8), cv2.IMREAD_COLOR)
            if img is None:
                log_proses(image_filename, "Gagal: Tidak dapat membaca gambar input", "encrypt")
                raise ValueError("Gagal membaca gambar input")

            # AES Encryption
            aes_start = time.perf_counter()
            key_bytes = hashlib.sha256(password.encode()).digest()
            iv = os.urandom(16)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            padded_text = pad(text.encode('utf-8'), AES.block_size)
            encrypted_bytes = iv + cipher.encrypt(padded_text)
            aes_duration = (time.perf_counter() - aes_start) * 1000

            # LSB Embedding
            lsb_start = time.perf_counter()
            uploads_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
            os.makedirs(uploads_folder, exist_ok=True)
            output_filename = f"encrypted_{int(time.time())}.png"
            output_path = os.path.join(uploads_folder, output_filename)
            
            # Gunakan LSBSteganography
            success = LSBSteganography.embed(img, encrypted_bytes, output_path)
            if not success:
                log_proses(image_filename, "Gagal: Tidak dapat menyisipkan data ke gambar", "encrypt")
                raise RuntimeError("Gagal menyisipkan data ke gambar")
            lsb_duration = (time.perf_counter() - lsb_start) * 1000

            # Hitung metrik
            file_size = os.path.getsize(output_path) / 1024  # KB
            end_time = datetime.now()
            duration = round(time.time() - start, 2)
            
            # Log proses sukses
            log_proses(output_filename, "Berhasil", "encrypt")
            
            return jsonify({
                'status': 'success',
                'metrics': {
                    'aes_time': f"{aes_duration:.2f} ms",
                    'lsb_time': f"{lsb_duration:.2f} ms",
                    'file_size': f"{file_size:.2f} KB",
                    'total_time': f"{(aes_duration + lsb_duration):.2f} ms"
                },
                'download_url': url_for('main.download_file', filename=output_filename),
                'filename': output_filename
            })

        except Exception as e:
            logger.error(f"Error enkripsi: {str(e)}", exc_info=True)
            # Gunakan image_filename yang sudah didefinisikan di awal
            log_proses(image_filename, f"Gagal: {str(e)}", "encrypt")
            return jsonify({
                'status': 'error', 
                'message': f'Gagal proses enkripsi: {str(e)}'
            }), 500

    return render_template('enkripsi.html')

@main.route('/extract', methods=['GET', 'POST'])
def extract_route():
    if request.method == 'POST':
        start_time = datetime.now()
        start = time.time()

        steg_image = request.files.get('steg_image')
        key = request.form.get('key')
        estimated_length = request.form.get('data_length')

        if not steg_image or not steg_image.filename or not key or not estimated_length:
            flash('Semua isian wajib diisi (gambar, panjang data, dan kunci).', 'error')
            return redirect(request.url)

        try:
            estimated_length = int(estimated_length)
            if estimated_length <= 0:
                raise ValueError("Panjang data harus lebih dari nol.")
        except ValueError:
            flash('Panjang data harus berupa angka valid.', 'error')
            return redirect(request.url)

        try:
            uploads_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
            os.makedirs(uploads_folder, exist_ok=True)
            filename = secure_filename(steg_image.filename)
            file_path = os.path.join(uploads_folder, filename)
            steg_image.save(file_path)

            # Ekstraksi data menggunakan LSBSteganography
            extracted_bytes = LSBSteganography.extract(cv2.imread(file_path))
            if not extracted_bytes:
                raise ValueError("Gagal mengekstrak data dari gambar")

            # Dekripsi menggunakan fungsi yang sudah diperbaiki
            decrypted_message = decrypt_data(extracted_bytes, key)

            output_filename = f"decrypted_{int(time.time())}.txt"
            output_path = os.path.join(uploads_folder, output_filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_message)
            log_proses(filename, "Berhasil", "decrypt")

            return render_template(
                'extract.html',
                decrypted_message=decrypted_message,
                output_filename=output_filename
            )

        except Exception as e:
            logger.error(f"[ERROR] Ekstrak/dekripsi gagal: {str(e)}", exc_info=True)
            log_proses(steg_image.filename if steg_image else "unknown", f"Gagal: {str(e)}", "decrypt")
            flash(f'Gagal proses dekripsi: {str(e)}', 'error')
            return redirect(request.url)

    return render_template('extract.html')

@main.route('/admin')
def admin():
    # Periksa apakah admin sudah login
    if not session.get('admin_logged_in'):
        return redirect(url_for('main.login'))
    
    try:
        q = request.args.get('q', '')  # Untuk fitur pencarian
        
        with db_manager.get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                if q:
                    cursor.execute("""
                        SELECT id, tipe, nama_file, 
                               DATE_FORMAT(waktu, '%d-%m-%Y %H:%i:%s') as waktu_format, 
                               status 
                        FROM log_proses 
                        WHERE nama_file LIKE %s 
                        ORDER BY waktu DESC
                    """, (f"%{q}%",))
                else:
                    cursor.execute("""
                        SELECT id, tipe, nama_file, 
                               DATE_FORMAT(waktu, '%d-%m-%Y %H:%i:%s') as waktu_format, 
                               status 
                        FROM log_proses 
                        ORDER BY waktu DESC
                    """)
                
                logs = cursor.fetchall()
                
        return render_template('juan/admin.html', logs=logs)
        
    except Exception as e:
        print(f"Error fetching logs: {e}")
        flash('Gagal memuat data log', 'error')
        return render_template('juan/admin.html', logs=[])

@main.route('/admin/logs/<int:log_id>', methods=['DELETE'])
def delete_log(log_id):
    try:
        with db_manager.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM log_proses WHERE id = %s", (log_id,))
                conn.commit()
        return jsonify({'message': 'Log berhasil dihapus!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/download-encrypted/<filename>')
def download_encrypted(filename):
    uploads_folder = current_app.config['UPLOAD_FOLDER']
    safe_filename = secure_filename(filename)
    file_path = os.path.join(uploads_folder, safe_filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File tidak ditemukan"}), 404
        
    return send_from_directory(uploads_folder, safe_filename, as_attachment=True, cache_timeout=0)

@main.route("/reset-logs", methods=["POST"])
def reset_logs_route():
    conn = get_mysql_connection()
    cursor = conn.cursor()
    try:
        # Hapus semua data di tabel log_proses
        cursor.execute("DELETE FROM log_proses")
        # Reset auto increment ke 1
        cursor.execute("ALTER TABLE log_proses AUTO_INCREMENT = 1")
        conn.commit()
    except Exception as e:
        conn.rollback()
        # Bisa tambahkan logging error di sini
    finally:
        cursor.close()
        conn.close()
    return redirect("/admin")

@main.before_request
def check_email_config():
    if request.endpoint == 'main.send_email_confirmation':
        if not all([
            os.getenv("EMAIL_USER"),
            os.getenv("EMAIL_PASSWORD")
        ]):
            return jsonify({
                'status': 'error',
                'message': 'Email service not configured'
            }), 503

# Route untuk kirim email
@main.route('/send-email', methods=['POST'])
def send_email_confirmation():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'filename' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Email and filename are required'
            }), 400

        email = data['email'].strip()
        filename = secure_filename(data['filename'])
        
        # Validasi format email
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return jsonify({
                'status': 'error',
                'message': 'Invalid email format'
            }), 400

        # Dapatkan path file yang aman
        uploads_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
        file_path = os.path.join(uploads_folder, filename)
        
        # Verifikasi file exists
        if not os.path.isfile(file_path):
            current_app.logger.error(f"File not found: {file_path}")
            return jsonify({
                'status': 'error',
                'message': 'Encrypted file not found on server',
                'debug': {
                    'requested_file': filename,
                    'resolved_path': file_path,
                    'directory_exists': os.path.exists(uploads_folder),
                    'files_in_directory': os.listdir(uploads_folder)
                }
            }), 404

        # Kirim email
        subject = "Your Encrypted File"
        body = f"""Hello,

Please find attached your encrypted file.
File name: {filename}

Important:
- Keep your encryption key safe
- This file contains hidden encrypted data

Thank you for using our service.
"""
        if send_email(email, subject, body, file_path):
            return jsonify({
                'status': 'success',
                'message': 'Email sent successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to send email'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Email sending error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while sending email',
            'error': str(e)
        }), 500
    

@main.route('/clear_pending', methods=['POST'])
def clear_pending():
    session.pop('pending_email', None)
    return '', 204

@main.route('/performance-metrics')
def get_performance_metrics():
    """Endpoint untuk mendapatkan data performa historis"""
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        query = """
            SELECT 
                DATE(waktu) as date,
                AVG(TIME_TO_SEC(TIMEDIFF(end_time, start_time))) * 1000 as avg_time
            FROM log_proses
            WHERE tipe = 'ENCRYPT'
            GROUP BY DATE(waktu)
            ORDER BY date DESC
            LIMIT 7
        """
        cursor.execute(query)
        metrics = cursor.fetchall()
        
        return jsonify({
            'status': 'success',
            'metrics': metrics
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    finally:
        cursor.close()
        conn.close()    

@main.app_errorhandler(404)
def handle_not_found(e):
    return jsonify({"error": "Endpoint tidak ditemukan"}), 404

@main.app_errorhandler(500)
def handle_server_error(e):
    return jsonify({"error": "Kesalahan server internal"}), 500