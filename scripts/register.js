// Objeto de reglas centralizado para evitar duplicar lógica
const PASSWORD_RULES = {
    min: (val) => val.length >= 8,
    mayus: (val) => /[A-Z]/.test(val),
    minus: (val) => /[a-z]/.test(val),
    num: (val) => /\d/.test(val),
    esp: (val) => /[!@#$%^&*(),.?":{}|<>]/.test(val)
};

// Verificar que las contraseñas del registro sean iguales.
function verificarPassword(password, passwordRepeat, email, inputElement, inputExtra) {
    // 1. Verificar Coincidencia
    if (password !== passwordRepeat) {
        mostrarError("Las contraseñas no coinciden.", inputExtra, true);
        inputExtra.focus();
        return false;
    }

    // 2. Verificar Requisitos Básicos (Lista visual)
    // Recorre todas las reglas del objeto PASSWORD_RULES
    const cumpleBasicos = Object.values(PASSWORD_RULES).every(rule => rule(password));
    if (!cumpleBasicos) {
        mostrarError("La contraseña no cumple con todos los requisitos de seguridad.", inputElement, true);
        inputElement.focus();
        return false;
    }

    // 3. Verificar números repetidos (ej: 111, 555)
    // Regex: (\d) captura un dígito, \1\1 busca ese mismo dígito 2 veces más
    if (/(\d)\1\1/.test(password)) {
        mostrarError("No repitas el mismo número 3 veces seguidas.", inputElement, true);
        inputElement.focus();
        return false;
    }

    // 4. Verificar contenido del email
    if (email) {
        const usuarioEmail = email.split('@')[0].toLowerCase();
        // Solo validamos si el usuario tiene al menos 4 letras para evitar falsos positivos con nombres cortos
        if (usuarioEmail.length >= 4 && password.toLowerCase().includes(usuarioEmail)) {
            mostrarError("La contraseña no debe contener tu nombre de usuario/email.", inputElement, true);
            inputElement.focus();
            return false;
        }
    }

    // Si pasa todo, limpiamos errores
    mostrarError("", inputElement, false); // Ocultar error
    return true;
}

//Boton de registro
function prepararVistaRegister() {
    const form = document.getElementById("register_form");
    if (!form) return;

    const email_input = form.querySelector('input[name="email"]');
    const password_input = form.querySelector('input[name="password"]');
    const password_repeat_input = form.querySelector('input[name="password-repeat"]');
    const lista = document.getElementById("lista-requisitos");

    // --- LÓGICA VISUAL (Feedback en tiempo real) ---
    if (lista) {
        password_input.addEventListener("input", () => {
            const valor = password_input.value;
            // Usamos el objeto global PASSWORD_RULES
            Object.keys(PASSWORD_RULES).forEach(key => {
                const elemento = lista.querySelector(`[data-id="${key}"]`);
                if (elemento) {
                    const esValido = PASSWORD_RULES[key](valor);
                    elemento.style.color = esValido ? "#019DE2" : "";
                    elemento.style.opacity = esValido ? "1" : "0.6";
                }
            });
        });
    }

    // --- LIMPIEZA DE ERRORES ---
    [email_input, password_input, password_repeat_input].forEach(input => {
        input.addEventListener("input", () => {
             // Limpia el error visual del input rojo si el usuario empieza a escribir
            if(input.classList.contains("different-password")) input.classList.remove("different-password");
            
            // Intenta borrar el mensaje de error si existe
            const errorLabel = input.closest(".input")?.nextElementSibling;
            if (errorLabel && errorLabel.classList.contains("message_error_input")) {
                errorLabel.remove();
            }
        });
    });

    // --- ENVÍO DEL FORMULARIO ---
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        
        // Limpiamos cualquier error previo general
        mostrarError(""); 
        alternarBotonFormulario(); // Deshabilita botón / pone spinner

        const email = email_input.value.trim();
        const password = password_input.value;
        const password_repeat = password_repeat_input.value;

        // LLAMADA A LA NUEVA FUNCIÓN DE VERIFICACIÓN
        const esValido = verificarPassword(password, password_repeat, email, password_input, password_repeat_input);

        if (esValido) {
            try {
                const resultado = await registrarUsuario(email, password);
                
                if (resultado.status === "success") {
                    navegarA("login");
                } else {
                    // Error de API (ej: usuario ya existe)
                    if (resultado.code === 101) {
                        email_input.focus();
                        mostrarError(resultado.message, email_input, true);
                    } else {
                        mostrarError(resultado.message);
                    }
                    alternarBotonFormulario(); // Reactiva botón
                }
            } catch (error) {
                mostrarError("Error de conexión con el servidor.");
                alternarBotonFormulario("Registrarse");
            }
        } else {
            // Si la validación local falló (verificarPassword ya mostró el error específico)
            alternarBotonFormulario("Registrarse");
        }
    });
}