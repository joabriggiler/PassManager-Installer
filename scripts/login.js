function prepararVistaLogin() {
    const form = document.getElementById("login_form");
    if (!form) return;

    const email_input = form.querySelector('input[name="email"]');
    const password_input = form.querySelector('input[name="password"]');

    const emailGuardado = localStorage.getItem("user_email");
    if (emailGuardado && email_input) {
        email_input.value = emailGuardado;
        // opcional: foco inteligente
        if (password_input) password_input.focus();
    }

    // --- LIMPIEZA DE ERRORES ---
    [email_input, password_input].forEach(input => {
        input.addEventListener("input", () => {
            if(input.classList.contains("different-password")) input.classList.remove("different-password");
            
            const errorLabel = input.closest(".input")?.nextElementSibling;
            if (errorLabel && errorLabel.classList.contains("message_error_input")) {
                errorLabel.remove();
            }
        });
    });

    form.addEventListener("submit", async function(event){
        event.preventDefault();
        mostrarError("");
        alternarBotonFormulario();

        let avisoLento = false;
        const timerLento = setTimeout(() => {
            avisoLento = true;
            mostrarError(
                "Usamos servidores de bajo consumo. El primer inicio puede tardar más de lo normal. Gracias por tu paciencia.",
                password_input,
                true
            );
        }, 5000);
        
        const email = email_input.value;
        const password = password_input.value;

        try {
            const resultado = await loginUsuario(email, password);
            clearTimeout(timerLento);

            if (resultado.status === "success") {
                localStorage.setItem("user_email", email);
                
                navegarA("dashboard"); 
            } else {
                if (resultado.code === 102) { // Usuario no existe
                    email_input.focus();
                    mostrarError(resultado.message, email_input, true);
                } 
                
                if (resultado.code === 103) { // Password incorrecta
                    password_input.value = "";
                    password_input.focus();
                    mostrarError(resultado.message, password_input, true);
                }

                alternarBotonFormulario();
            }
        } catch (error) {
            clearTimeout(timerLento);
            alternarBotonFormulario();
        }
    });
}