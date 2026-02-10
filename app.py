from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Inicializamos la aplicación
app = Flask(__name__)

# CONFIGURACIÓN
app.config['SECRET_KEY'] = 'una_clave_muy_secreta_temporal' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///boveda.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializamos Base de Datos y Login
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Si intentas entrar a dashboard sin permiso, te manda aquí

# --- MODELOS DE BASE DE DATOS ---
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
    return render_template('base.html') # Muestra la página de inicio vacía (por ahora)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Verificar si ya existe
        user = User.query.filter_by(username=username).first()
        if user:
            flash('El usuario ya existe. Intenta otro.')
            return redirect(url_for('register'))
        
        # Crear nuevo usuario (Con contraseña hasheada básica)
        new_user = User(username=username, password=generate_password_hash(password, method='scrypt'))
        db.session.add(new_user)
        db.session.commit()
        
        flash('Cuenta creada. Ahora inicia sesión.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # Verificar contraseña
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.')
            
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        # Crear nuevo secreto vinculado al usuario actual
        new_secret = Secret(title=title, content=content, user_id=current_user.id)
        db.session.add(new_secret)
        db.session.commit()
        flash('¡Secreto guardado en la bóveda!')
        
    # Obtener SOLO los secretos del usuario conectado
    user_secrets = Secret.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', secrets=user_secrets, name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.')
    return redirect(url_for('login'))

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_secret(id):
    secret = Secret.query.get_or_404(id)
    
    # SEGURIDAD: Verificar que el secreto pertenece al usuario actual
    if secret.user_id != current_user.id:
        flash('¡Acción no autorizada! Este secreto no es tuyo.')
        return redirect(url_for('dashboard'))

    db.session.delete(secret)
    db.session.commit()
    flash('Secreto eliminado correctamente.')
    return redirect(url_for('dashboard'))

# INICIAR APP
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

