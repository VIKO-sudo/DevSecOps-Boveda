from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from flask import session
import pyotp
import qrcode
import base64
import os
import logging
import json
import io
import zipfile
import re
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Cargar variables ocultas
load_dotenv()

# Inicializamos la aplicación
app = Flask(__name__)

# CONFIGURACIÓN
app.config['SECRET_KEY'] = 'una_clave_muy_secreta_temporal' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///boveda.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- MOTOR DE CIFRADO DE BASE DE DATOS (ENCRYPTION AT REST) ---
ENCRYPTION_KEY = os.getenv('FERNET_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("CRÍTICO: Falta FERNET_KEY en el archivo .env")
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

# --- SEGURIDAD: LIMITADOR DE INTENTOS ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# --- SEGURIDAD: LOGS (AUDITORÍA) ---
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    filename='logs/audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Inicializamos Base de Datos y Login
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    secrets = db.relationship('Secret', backref='owner', lazy=True)
    
    # --- NUEVO: Account Lockout ---
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # --- NUEVO: Preparación para 2FA/MFA ---
    totp_secret = db.Column(db.String(32), nullable=True)
    is_mfa_enabled = db.Column(db.Boolean, default=False)

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False) # Aquí se guardará el texto cifrado
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    # Versión moderna de SQLAlchemy 2.0
    return db.session.get(User, int(user_id))

# --- RUTAS PRINCIPALES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VALIDACIÓN REGEX: Min 8 chars, 1 mayúscula, 1 minúscula, 1 número
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$', password):
            flash('La contraseña debe tener mínimo 8 caracteres, incluir una mayúscula, una minúscula y un número.')
            return redirect(url_for('register'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Error en el registro. Verifique sus datos.') # OpSec: Evitamos confirmación de usuario
            logging.warning(f'Intento de registro fallido: Usuario {username} ya existe.')
            return redirect(url_for('register'))
        
        new_user = User(username=username, password=generate_password_hash(password, method='scrypt'))
        db.session.add(new_user)
        db.session.commit()
        
        logging.info(f'Nuevo usuario registrado: {username}')
        flash('Cuenta creada. Ahora inicia sesión.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            # 1. VERIFICAR SI LA CUENTA ESTÁ CONGELADA
            if user.locked_until and user.locked_until > datetime.utcnow():
                tiempo_restante = (user.locked_until - datetime.utcnow()).seconds // 60
                flash(f'Cuenta bloqueada por seguridad. Intenta de nuevo en {tiempo_restante} minutos.')
                logging.warning(f'Intento de acceso a cuenta bloqueada: {username}')
                return redirect(url_for('login'))

            # 2. VERIFICAR CONTRASEÑA
            if check_password_hash(user.password, password):
                user.failed_logins = 0
                user.locked_until = None
                db.session.commit()
                
                # --- NUEVO: INTERCEPTOR DE 2FA ---
                if user.is_mfa_enabled:
                    # Guardamos temporalmente su ID en la sesión, pero NO lo logueamos aún
                    session['pending_user_id'] = user.id
                    return redirect(url_for('login_2fa'))
                
                # Si no tiene 2FA, lo dejamos pasar directo
                login_user(user)
                logging.info(f'Inicio de sesión exitoso: {username}')
                return redirect(url_for('dashboard'))
        
            else:
                # Login Fallido: Sumamos 1 al contador de errores
                user.failed_logins += 1
                if user.failed_logins >= 5:
                    # Al 5to error, bloqueamos la cuenta por 15 minutos
                    user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                    logging.warning(f'CUENTA CONGELADA: {username} excedió intentos de contraseña.')
                    flash('Demasiados intentos fallidos. Cuenta bloqueada por 5 minutos')
                else:
                    intentos_restantes = 5 - user.failed_logins
                    logging.warning(f'Fallo de inicio de sesión para: {username}. Quedan {intentos_restantes} intentos.')
                    flash(f'Usuario o contraseña incorrectos. Quedan {intentos_restantes} intentos.')
                db.session.commit()
        else:
            # Si el usuario no existe, mensaje genérico (OpSec)
            flash('Usuario o contraseña incorrectos.')
            
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        title = request.form.get('title')
        raw_content = request.form.get('content')
        
        # CIFRADO AL VUELO: Encriptamos antes de tocar la base de datos
        encrypted_content = cipher_suite.encrypt(raw_content.encode('utf-8')).decode('utf-8')
        
        new_secret = Secret(title=title, content=encrypted_content, user_id=current_user.id)
        db.session.add(new_secret)
        db.session.commit()
        logging.info(f'Usuario {current_user.username} creó un secreto: {title}')
        flash('¡Secreto guardado en bóveda cifrada!')
        
    # RECUPERACIÓN: Extraemos de la DB y desciframos en memoria RAM para mostrar
    user_secrets = Secret.query.filter_by(user_id=current_user.id).all()
    for s in user_secrets:
        try:
            s.content = cipher_suite.decrypt(s.content.encode('utf-8')).decode('utf-8')
        except:
            s.content = "⚠️ ERROR: Dato corrupto"
            
    return render_template('dashboard.html', secrets=user_secrets, name=current_user.username)

@app.route('/edit/<int:id>', methods=['POST'])
@login_required
def edit_secret(id):
    secret = Secret.query.get_or_404(id)
    if secret.user_id != current_user.id:
        logging.warning(f'Intento de IDOR bloqueado. Usuario {current_user.username}.')
        flash('¡Acción no autorizada!')
        return redirect(url_for('dashboard'))

    new_title = request.form.get('title')
    new_raw_content = request.form.get('content')
    
    # CIFRAMOS LA NUEVA CONTRASEÑA
    encrypted_content = cipher_suite.encrypt(new_raw_content.encode('utf-8')).decode('utf-8')
    
    secret.title = new_title
    secret.content = encrypted_content
    db.session.commit()
    logging.info(f'Usuario {current_user.username} editó el secreto ID {id}')
    flash('Credencial actualizada correctamente.')
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_secret(id):
    secret = Secret.query.get_or_404(id)
    if secret.user_id != current_user.id:
        flash('¡Acción no autorizada!')
        return redirect(url_for('dashboard'))

    db.session.delete(secret)
    db.session.commit()
    logging.info(f'Usuario {current_user.username} eliminó un secreto.')
    flash('Secreto eliminado.')
    return redirect(url_for('dashboard'))

@app.route('/export', methods=['POST'])
@login_required
def export_vault():
    export_password = request.form.get('export_password')
    if len(export_password) < 4:
        flash('La contraseña debe tener al menos 4 caracteres.')
        return redirect(url_for('dashboard'))
    
    # Extraemos y desciframos la DB local para poder volver a cifrarla con la clave del usuario
    user_secrets = Secret.query.filter_by(user_id=current_user.id).all()
    secrets_list = []
    for s in user_secrets:
        try:
            raw_content = cipher_suite.decrypt(s.content.encode('utf-8')).decode('utf-8')
        except:
            raw_content = "ERROR"
        secrets_list.append({'Plataforma': s.title, 'Credencial': raw_content})
        
    secrets_json = json.dumps(secrets_list).encode('utf-8')
    
    salt = os.urandom(16) 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000, 
    )
    key = kdf.derive(export_password.encode())
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, secrets_json, None)
    
    final_encrypted_data = salt + nonce + ciphertext

    html_hacker = """<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Rescate de Bóveda</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:40px;}
.box{border:1px solid #30363d;padding:20px;background:#161b22;border-radius:8px;max-width:600px;margin:auto;}
input,button{width:100%;margin:10px 0;padding:12px;background:#0d1117;color:#58a6ff;border:1px solid #30363d;}
button{background:#238636;color:white;cursor:pointer;font-weight:bold;}button:hover{background:#2ea043;}
#resultado{margin-top:20px;white-space:pre-wrap;color:#3fb950;display:none;}</style></head>
<body><div class="box"><h2 style="color:#58a6ff;">🛡️ Desencriptador Offline</h2>
<p>1. Selecciona <b>boveda_datos.enc</b></p><input type="file" id="fileInput">
<p>2. Ingresa Contraseña</p><input type="password" id="passInput">
<button onclick="decrypt()">🔓 DESBLOQUEAR</button><div id="resultado"></div></div>
<script>async function decrypt(){const file=document.getElementById('fileInput').files[0];const password=document.getElementById('passInput').value;const out=document.getElementById('resultado');if(!file||!password)return;try{const arrayBuffer=await file.arrayBuffer();const data=new Uint8Array(arrayBuffer);const salt=data.slice(0,16);const iv=data.slice(16,28);const ciphertext=data.slice(28);const passKey=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),{name:"PBKDF2"},false,["deriveKey"]);const aesKey=await crypto.subtle.deriveKey({name:"PBKDF2",salt:salt,iterations:600000,hash:"SHA-256"},passKey,{name:"AES-GCM",length:256},false,["decrypt"]);const decrypted=await crypto.subtle.decrypt({name:"AES-GCM",iv:iv},aesKey,ciphertext);const json=JSON.parse(new TextDecoder().decode(decrypted));let html="<h3>✅ DATOS:</h3>\\n";json.forEach(item=>{html+=`📌 <b>${item.Plataforma}:</b> ${item.Credencial}\\n`;});out.innerHTML=html;out.style.display='block';}catch(e){alert("❌ Error.");}}</script></body></html>"""

    txt_instrucciones = f"""KIT DE RESCATE - {current_user.username.upper()}\n===================\n1. Extrae el ZIP.\n2. Abre Rescate_Offline.html.\n3. Selecciona boveda_datos.enc y pon tu clave."""

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('boveda_datos.enc', final_encrypted_data)
        zf.writestr('INSTRUCCIONES.txt', txt_instrucciones)
        zf.writestr('Rescate_Offline.html', html_hacker)
    
    memory_file.seek(0)
    return send_file(memory_file, as_attachment=True, download_name=f'Kit_Rescate_{current_user.username}.zip', mimetype='application/zip')

@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.is_mfa_enabled:
        flash('El Autenticador ya está activado en tu cuenta.')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        token = request.form.get('token')
        # Verificamos si el código que puso en su cel es correcto
        totp = pyotp.TOTP(session.get('temp_totp_secret'))
        if totp.verify(token):
            current_user.totp_secret = session['temp_totp_secret']
            current_user.is_mfa_enabled = True
            db.session.commit()
            session.pop('temp_totp_secret', None) # Limpiamos la memoria
            flash('¡Autenticación de Dos Factores activada con éxito! Nivel de seguridad al máximo. 🛡️')
            return redirect(url_for('dashboard'))
        else:
            flash('Código incorrecto. Asegúrate de leer bien los 6 dígitos.')
    
    # Si entra por primera vez (GET), le generamos un secreto único
    if 'temp_totp_secret' not in session:
        session['temp_totp_secret'] = pyotp.random_base32()
    
    secret = session['temp_totp_secret']
    # Creamos el link estándar que entienden las apps de MFA
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name="DevSecOps Vault")
    
    # Dibujamos el QR en la memoria RAM y lo convertimos a texto Base64 para enviarlo al HTML
    import io
    qr = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return render_template('setup_2fa.html', secret=secret, qr_b64=qr_base64)

@app.route('/login_2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token')
        # --- VERSIÓN CORREGIDA PARA SQLALCHEMY 2.0 ---
        user = db.session.get(User, session['pending_user_id']) 
        
        totp = pyotp.TOTP(user.totp_secret)
        # ... (el resto sigue igual)
        
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            # El código es correcto. Lo logueamos de verdad.
            session.pop('pending_user_id', None)
            login_user(user)
            logging.info(f'Inicio de sesión 2FA exitoso: {user.username}')
            return redirect(url_for('dashboard'))
        else:
            logging.warning(f'Intento fallido de 2FA para usuario ID: {user.id}')
            flash('Código 2FA incorrecto o expirado.')
            
    return render_template('login_2fa.html')
@app.route('/logout')  # <--- ¡ESTA LÍNEA ES LA QUE TE FALTA!
@login_required        # <--- Y ESTA TAMBIÉN (Para mayor seguridad)
def logout():
    logout_user()
    flash('Has cerrado sesión.')
    return redirect(url_for('login'))

@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f'IP bloqueada temporalmente: {get_remote_address()}')
    return render_template('base.html', content="""
        <div class="container text-center mt-5 pt-5">
            <h1 class="display-1 text-danger">⏳</h1>
            <h2 class="text-white">Demasiados Intentos</h2>
            <p class="text-muted">Por seguridad, tu IP ha sido pausada temporalmente.<br>Espera 60 segundos y vuelve a intentarlo.</p>
            <a href="/" class="btn btn-outline-light mt-3">Volver al inicio</a>
        </div>
    """), 429

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)