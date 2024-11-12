from flask import Flask, render_template, request, redirect, session, url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify

from datetime import datetime, timedelta,timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import secrets
import random
import string



# Configuración de la aplicación Flask
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'  # Puedes cambiar esto a otra URI de base de datos
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mi_clave_secreta'  # Asegúrate de que esta clave sea suficientemente segura
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Desactiva SameSite para pruebas
app.config['SESSION_COOKIE_SECURE'] = True  # Desactiva el uso de cookies seguras en HTTP para pruebas

# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tu_correo@gmail.com'
app.config['MAIL_PASSWORD'] = 'tu_contraseña'
mail = Mail(app)

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

@app.route('/solicitar_restablecimiento', methods=['POST'])
def solicitar_restablecimiento():
    email = request.form.get('email')
    usuario = Usuario.query.filter_by(email=email).first()
    
    if not usuario:
        return jsonify({"message": "El usuario no existe."}), 404

    # Generar un código de verificación de 6 dígitos
    codigo_verificacion = random.randint(100000, 999999)
    
    # Asignar el código de verificación y la expiración
    usuario.codigo_verificacion = codigo_verificacion
    usuario.codigo_expiracion = datetime.now() + timedelta(minutes=15)
    
    db.session.commit()

    # Enviar el correo con el código
    msg = Message('Código de verificación para restablecer la contraseña', sender='tu_email@dominio.com', recipients=[email])
    msg.body = f'Tu código de verificación es: {codigo_verificacion}'
    mail.send(msg)

    return jsonify({"message": "Se ha enviado un código de verificación a tu correo."}), 200

# @app.route('/restablecer_contraseña', methods=['GET', 'POST'])
# def restablecer_contraseña():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         # Verifica si el email existe en la base de datos
#         usuario = Usuario.query.filter_by(email=email).first()
#         if usuario:
#             # Lógica para enviar el código de verificación
#             return jsonify({"message": "Correo enviado con instrucciones para restablecer la contraseña."}), 200
#         else:
#             return jsonify({"message": "El correo no está registrado."}), 404
#     return render_template('restablecer_contraseña.html')

# Ruta para verificar el código y restablecer la contraseña
@app.route('/api/verify-code', methods=['POST'])
def verify_code():
    data = request.get_json()
    email = data.get('email')
    codigo_verificacion = data.get('codigo')
    new_password = data.get('password')

    usuario = Usuario.query.filter_by(email=email).first()

    if not usuario:
        return jsonify({"message": "El usuario no existe."}), 404

    # Verificar el código y la expiración
    if usuario.codigo_verificacion == codigo_verificacion and datetime.now() < usuario.codigo_expiracion:
        # Actualizar la contraseña (hashearla antes de guardarla)
        hashed_password = generate_password_hash(new_password)
        usuario.password = hashed_password
        usuario.codigo_verificacion = None  # Limpiar el código
        usuario.codigo_expiracion = None  # Limpiar la expiración
        db.session.commit()

        return jsonify({"message": "La contraseña se ha restablecido exitosamente."}), 200
    else:
        return jsonify({"message": "Código incorrecto o expirado."}), 400
    
# Función para generar un código de verificación
def generar_codigo_verificacion():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

# Ruta para restablecer contraseña
@app.route('/restablecer_contraseña', methods=['GET', 'POST'])
def restablecer_contraseña():
    if request.method == 'POST':
        email = request.form.get('email')
        # Verifica si el email existe en la base de datos
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario:
            # Genera el código de verificación
            codigo_verificacion = generar_codigo_verificacion()

            # Crea el mensaje
            msg = Message("Código de Verificación para Restablecer tu Contraseña",
                          recipients=[email])
            msg.body = f"Tu código de verificación es: {codigo_verificacion}"

            try:
                # Envía el correo
                mail.send(msg)
                flash('Se ha enviado un correo con el código de verificación', 'success')
                return redirect(url_for('verificar_codigo', email=email, codigo=codigo_verificacion))
            except Exception as e:
                flash(f'Ocurrió un error al enviar el correo: {str(e)}', 'danger')
                return redirect(url_for('restablecer_contraseña'))

        else:
            flash('El correo no está registrado', 'danger')
            return redirect(url_for('restablecer_contraseña'))
    return render_template('restablecer_contraseña.html')

# Ruta para verificar el código
@app.route('/verificar_codigo', methods=['GET', 'POST'])
def verificar_codigo():
    email = request.args.get('email')
    codigo_esperado = request.args.get('codigo')
    
    if request.method == 'POST':
        codigo_usuario = request.form.get('codigo')
        if codigo_usuario == codigo_esperado:
            # Aquí puedes permitir al usuario restablecer su contraseña
            flash('Código verificado correctamente. Puedes restablecer tu contraseña.', 'success')
            return redirect(url_for('cambiar_contraseña', email=email))
        else:
            flash('Código incorrecto. Intenta nuevamente.', 'danger')
    
    return render_template('verificar_codigo.html')

# Ruta para cambiar la contraseña
@app.route('/cambiar_contraseña', methods=['GET', 'POST'])
def cambiar_contraseña():
    # Aquí puedes implementar el cambio de contraseña
    pass
if __name__ == "__main__":
    app.run(debug=True)