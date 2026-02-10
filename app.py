from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging

# Inicializamos la aplicación
app = Flask(__name__)

# CONFIGURACIÓN
app.config['SECRET_KEY'] = 'una_clave_muy_secreta_temporal' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///boveda.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- SEGURIDAD: LIMITADOR DE INTENTOS (RATE LIMITING) ---
# Evita ataques de fuerza bruta y DoS (que te peten la laptop)
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

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- RUTAS ---

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute") # PROTECCIÓN: Solo 3 intentos de registro por minuto
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VALIDACIÓN DE CONTRASEÑA (Política de Seguridad)
        if len(password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres.')
            return redirect(url_for('register'))

        user = User.query.filter_by(username=username).first()
        if user:
            # NOTA DE SEGURIDAD: Aquí podríamos poner un mensaje genérico para evitar enumeración,
            # pero por usabilidad escolar diremos que ya existe.
            flash('El usuario ya existe.')
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
@limiter.limit("5 per minute") # PROTECCIÓN: Escudo contra fuerza bruta
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            logging.info(f'Inicio de sesión exitoso: {username}')
            return redirect(url_for('dashboard'))
        else:
            logging.warning(f'Fallo de inicio de sesión para: {username}')
            # SEGURIDAD: Mensaje genérico para no revelar si falló el usuario o la pass
            flash('Usuario o contraseña incorrectos.')
            
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        new_secret = Secret(title=title, content=content, user_id=current_user.id)
        db.session.add(new_secret)
        db.session.commit()
        logging.info(f'Usuario {current_user.username} creó un secreto: {title}')
        flash('¡Secreto guardado!')
        
    user_secrets = Secret.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', secrets=user_secrets, name=current_user.username)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_secret(id):
    secret = Secret.query.get_or_404(id)
    
    if secret.user_id != current_user.id:
        logging.warning(f'ALERTA DE SEGURIDAD: Usuario {current_user.username} intentó borrar secreto ID {id} que no es suyo.')
        flash('¡Acción no autorizada!')
        return redirect(url_for('dashboard'))

    title_backup = secret.title
    db.session.delete(secret)
    db.session.commit()
    logging.info(f'Usuario {current_user.username} eliminó el secreto: {title_backup}')
    flash('Secreto eliminado.')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logging.info(f'Cierre de sesión: {current_user.username}')
    logout_user()
    flash('Has cerrado sesión.')
    return redirect(url_for('login'))

# MANEJO DE ERRORES DE RATE LIMIT (Para que se vea bonito cuando te bloquean)
@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f'IP bloqueada por exceso de intentos: {get_remote_address()}')
    return "<h1>⛔ CALMA HACKER ⛔</h1><p>Has excedido el número de intentos permitidos. Tu IP ha sido registrada.</p>", 429

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)
