// Validación del formulario
document.getElementById('loginForm').addEventListener('submit', function(event) {
    // Evitar envío inmediato del formulario
    event.preventDefault();

    // Obtener los valores de email y contraseña
    let email = document.getElementById('email').value;
    let password = document.getElementById('contraseña').value;
    let errorMessage = document.getElementById('errorMessage');
    errorMessage.textContent = ''; // Limpiar mensajes anteriores

    // Expresión regular para validar el email (formato correcto)
    let emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    // Expresión regular para validar la contraseña (mínimo 8 caracteres, letras y números)
    let passwordRegex = /^[A-Za-z0-9]{8,}$/;

    // Validar formato del email
    if (!emailRegex.test(email)) {
        errorMessage.textContent = 'El email contiene caracteres incorrectos o tiene un formato inválido.';
        return;
    }

    // Validar formato de la contraseña
    if (!passwordRegex.test(password)) {
        errorMessage.textContent = 'La contraseña debe tener al menos 8 caracteres, usar letras y/o números.';
        return;
    }

    // Si todo es válido, enviar el formulario
    this.submit();
});
