document.getElementById('registroForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Evitar el envío inmediato del formulario

    // Obtener los valores de los campos
    const nombreapellido = document.getElementById('nombreApellido').value;
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('contraseña').value;
    const confirmPassword = document.getElementById('confirmarContraseña').value;
    const errorMessage = document.getElementById('errorMessage');

    errorMessage.textContent = ''; // Limpiar mensajes anteriores

    // Expresión para validar email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    // Expresión para validar nombre y apellido (mínimo 6 caracteres y solo letras)
    const nombreapellidoRegex = /^[A-Za-z\s]{6,}$/;
    // Expresión para validar la contraseña (mínimo 8 caracteres, letras y números)
    const passwordRegex = /^[A-Za-z0-9]{8,}$/;

//-----------------------------------------------------------------------------------------------
    // Validar nombre y apellido
    if (!nombreapellidoRegex.test(nombreapellido)) {
        errorMessage.textContent = 'Ingrese un nombre valido';
        return;
    }
    //Validacion de email
    if (!emailRegex.test(email)) {
        errorMessage.textContent = 'Por favor, ingrese un email válido.';
        return;
    }
    // Validación de la contraseña
    if (!passwordRegex.test(password)) {
        errorMessage.textContent = 'La contraseña debe tener al menos 8 caracteres, usar letras y/o números.';
        return;
    }

    // Validación de la confirmación de la contraseña
    if (password !== confirmPassword) {
        errorMessage.textContent = 'Las contraseñas no coinciden.';
        return;
    }
   
    // Si todo es válido, puedes enviar el formulario
    // alert('Registro exitoso'); // Placeholder para el envío
    this.submit(); // Enviar el formulario si todo es válido
});