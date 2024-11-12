from flask import Flask, render_template, request, redirect, session, url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify

import random
from datetime import datetime, timedelta,timezone
#-------------------------------------------------------------
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash
import sqlite3




# Configuración de la aplicación Flask
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'  # Puedes cambiar esto a otra URI de base de datos
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mi_clave_secreta'  # Asegúrate de que esta clave sea suficientemente segura
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Desactiva SameSite para pruebas
app.config['SESSION_COOKIE_SECURE'] = True  # Desactiva el uso de cookies seguras en HTTP para pruebas
#-------------------------------------
#Agregacion
app.secret_key = 'mi_clave_secreta'  # Clave secreta para sesiones y tokens
s = URLSafeTimedSerializer(app.secret_key)

# Configuración del correo
SMTP_SERVER = 'smtp.tuservidor.com'
SMTP_PORT = 587
SMTP_USER = 'tu_email@example.com'
SMTP_PASSWORD = 'tu_contraseña'
#-------------------------------------
db = SQLAlchemy(app)

# Modelo de datos para usuarios
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombreapellido= db.Column(db.String(100),nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)  # Token de restablecimiento de contraseña
    token_expiration = db.Column(db.DateTime, nullable=True)  # Fecha de expiración del token
    codigo_verificacion = db.Column(db.Integer, nullable=True)  # Código de verificación
    codigo_expiracion = db.Column(db.DateTime, nullable=True) 
    # def generate_reset_token(self):
    #      self.reset_token = secrets.token_urlsafe(20)  # Genera un token seguro
    #      self.token_expiration = datetime.now(timezone.utc) + timedelta(hours=1)  # Expira en 1 hora
    #      db.session.commit()

# Modelo de datos para Tareas
class Tarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    descripcion = db.Column(db.String(200), nullable=False)
# Modelo de datos para Eventos
class Evento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    fecha = db.Column(db.String(10), nullable=False)  # Formato 'YYYY-MM-DD'
    descripcion = db.Column(db.String(200), nullable=False)

# Modelo de datos para Comentarios
class Comentarios(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)  
    comentario = db.Column(db.Text, nullable=False)
 
# Relación con usuario
    usuario = db.relationship('Usuario', backref=db.backref('eventos', lazy=True))
# Crea las tablas si no existen
with app.app_context():
    db.create_all()

# Página principal
@app.route('/')
def index():
    return render_template('index.html')
# Página de registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombreapellido= request.form['nombreApellido']
        email = request.form['email']
        password = request.form['contraseña']
        confirm_password = request.form['confirmarContraseña']
        
        # Validar contraseñas
        if password != confirm_password:
            return render_template('registro.html', error_message="Las contraseñas no coinciden.")
        
        # Verificar si el email ya existe
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            return render_template('registro.html', error_message="El email ya está registrado.")
        # Guardar el nuevo usuario
        nuevo_usuario = Usuario(nombreapellido=nombreapellido,email=email, password=password)
        
        try:
            db.session.add(nuevo_usuario)  # Añadir el nuevo usuario a la sesión
            db.session.commit()  # Confirmar los cambios en la base de datos

            return redirect(url_for('index'))  # Redirigir a la página de login
        except Exception as e:
            db.session.rollback()  # Si hay un error, revertir cambios
            return render_template('registro.html', error_message="Hubo un error al registrar el usuario.")

    return render_template('registro.html')

# Página de login
@app.route('/index', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['contraseña']
        
        # Verificar las credenciales del usuario
        usuario = Usuario.query.filter_by(email=email, password=password).first()
        if usuario:
            # Guardar el ID y el email del usuario en la sesión
            session['user_id'] = usuario.id
            session['email'] = usuario.email  # Agrega el correo a la sesión
            print(f"Sesión iniciada para el usuario ID: {usuario.id}")  # Imprimir ID de usuario
            print("Session Data:", session)  # Imprimir la sesión completa

            return redirect('/TaskManager')  # Redirigir explícitamente
        else:
            print("El usuario no existe.")
            return render_template('index.html', error_message="Email o contraseña incorrectos.")
    
    return render_template('index.html')

# Ruta de logout
@app.route('/logout')
def logout():
    # Eliminar el usuario de la sesión
    session.pop('user_id', None)
    session.pop('email', None)  # Elimina también el email de la sesión
    print("Sesión cerrada.")
    return redirect('/index')  # Redirigir a la página de login

@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')

@app.route('/comentario')
def comentario():
    return render_template('Comentario.html')


@app.route('/TaskManager')
def TaskManager():
    return render_template('TaskManager.html')

#--------------------------------------------------
# Ruta para obtener las tareas del usuario actual
@app.route('/obtener_tareas', methods=['GET'])
def obtener_tareas():
    if 'user_id' not in session:
        return jsonify({'mensaje': 'No autorizado'}), 401

    usuario_id = session['user_id']
    tareas = Tarea.query.filter_by(usuario_id=usuario_id).all()
    return jsonify([{'id': tarea.id, 'descripcion': tarea.descripcion} for tarea in tareas])

# Ruta para agregar una nueva tarea
@app.route('/agregar_tarea', methods=['POST'])
def agregar_tarea():
    if 'user_id' not in session:
        return jsonify({'mensaje': 'No autorizado'}), 401

    descripcion = request.json.get('descripcion')
    usuario_id = session['user_id']
    nueva_tarea = Tarea(usuario_id=usuario_id, descripcion=descripcion)
    db.session.add(nueva_tarea)
    db.session.commit()
    return jsonify({'id': nueva_tarea.id, 'descripcion': nueva_tarea.descripcion})

# Ruta para eliminar una tarea
@app.route('/eliminar_tarea/<int:id>', methods=['DELETE'])
def eliminar_tarea(id):
    if 'user_id' not in session:
        return jsonify({'mensaje': 'No autorizado'}), 401

    tarea = Tarea.query.get(id)
    if tarea and tarea.usuario_id == session['user_id']:
        db.session.delete(tarea)
        db.session.commit()
        return jsonify({'mensaje': 'Tarea eliminada'})
    return jsonify({'mensaje': 'No encontrado o no autorizado'}), 404
#----------------------eventos----------------------------------
# Ruta para obtener los eventos del usuario actual
@app.route('/obtener_eventos', methods=['GET'])
def obtener_eventos():
    if 'user_id' not in session:
        return jsonify({'mensaje': 'No autorizado'}), 401

    usuario_id = session['user_id']
    eventos = Evento.query.filter_by(usuario_id=usuario_id).all()
    return jsonify([{'id': evento.id, 'fecha': evento.fecha, 'descripcion': evento.descripcion} for evento in eventos])

# Ruta para agregar un nuevo evento
@app.route('/agregar_evento', methods=['POST'])
def agregar_evento():
    if 'user_id' not in session:
        return jsonify({'mensaje': 'No autorizado'}), 401

    descripcion = request.json.get('descripcion')
    fecha = request.json.get('fecha')  # La fecha debe ser enviada en formato 'YYYY-MM-DD'
    usuario_id = session['user_id']
    nuevo_evento = Evento(usuario_id=usuario_id, fecha=fecha, descripcion=descripcion)
    db.session.add(nuevo_evento)
    db.session.commit()
    return jsonify({'id': nuevo_evento.id, 'fecha': nuevo_evento.fecha, 'descripcion': nuevo_evento.descripcion})

# Ruta para eliminar un evento
@app.route('/eliminar_evento/<int:id>', methods=['DELETE'])
def eliminar_evento(id):
    if 'user_id' not in session:
        return jsonify({'mensaje': 'No autorizado'}), 401

    evento = Evento.query.get(id)
    if evento and evento.usuario_id == session['user_id']:
        db.session.delete(evento)
        db.session.commit()
        return jsonify({'mensaje': 'Evento eliminado'})
    return jsonify({'mensaje': 'No encontrado o no autorizado'}), 404
#---------------------------------------------------------------------------
# Ruta para obtener los comentarios del usuario actual
@app.route('/comentar', methods=['POST'])
def comentar():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    descripcion = request.form.get('descripcion')
    
    # Verificar que el comentario no esté vacío
    if not descripcion:
        return render_template('Comentario.html', alert_message="El comentario no puede estar vacío.")
    
    # Crear un nuevo comentario con la fecha actual
    nuevo_comentario = Comentarios(
        usuario_id=session['user_id'],
        comentario=descripcion
    )
    
    try:
        db.session.add(nuevo_comentario)
        db.session.commit()
        # Redirigir o mostrar mensaje de éxito
        return render_template('Comentario.html', alert_message="Comentario guardado correctamente.")
    except Exception as e:
        db.session.rollback()
        return render_template('Comentario.html', alert_message="Hubo un error al guardar el comentario.")

#----------------------------------------------------------------------------------------------------------
#Agregacion
@app.route('/restablecer_contraseña', methods=['GET', 'POST'])
def restablecer_contraseña():
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = s.dumps(email, salt='restablecer-sal')
            enlace = url_for('restablecer_contraseña_token', token=token, _external=True)
            
            # Enviar correo electrónico
            msg = MIMEText(f'Haz clic en el siguiente enlace para restablecer tu contraseña: {enlace}')
            msg['Subject'] = 'Restablecimiento de Contraseña'
            msg['From'] = SMTP_USER
            msg['To'] = email

            try:
                server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, email, msg.as_string())
                server.quit()
                flash('Se ha enviado un correo para restablecer tu contraseña.', 'info')
            except Exception as e:
                flash(f'Error al enviar el correo: {e}', 'danger')
        else:
            flash('El correo no está registrado.', 'warning')

        return redirect(url_for('index'))
    
    return render_template('restablecer_contraseña.html')

@app.route('/restablecer_contraseña/<token>', methods=['GET', 'POST'])
def restablecer_contraseña_token(token):
    try:
        email = s.loads(token, salt='restablecer-sal', max_age=3600)  # Token válido por 1 hora
    except:
        flash('El enlace ha expirado o es inválido.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        nueva_contraseña = request.form['nueva_contraseña']
        confirmar_contraseña = request.form['confirmar_contraseña']

        if nueva_contraseña == confirmar_contraseña:
            hash_contraseña = generate_password_hash(nueva_contraseña)
            conn = sqlite3.connect('usuarios.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE usuarios SET contraseña = ? WHERE email = ?", (hash_contraseña, email))
            conn.commit()
            conn.close()

            flash('Tu contraseña ha sido actualizada.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Las contraseñas no coinciden.', 'warning')

    return render_template('nueva_contraseña.html')