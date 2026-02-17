//Boton de Guardado
function prepararVistaNewService() {
    if (!getAccessToken()) {
        navegarA("login");
        return;
    }

    const form = document.getElementById("new_service_form");
    if (!form) return;

    form.addEventListener("submit", async function(event){
        event.preventDefault();
        mostrarError("");
        alternarBotonFormulario();
        
        const service = document.getElementById("servicio_nombre").value;
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;
        const url = document.getElementById("url_service_input").value;

        try {
            const resultado = await guardarCuentaServicio(service, email, password, url);
            if (resultado.status === "success") {
                navegarA("dashboard"); // Volver al dashboard sin pestañeo
            } else {
                mostrarError(resultado.message);
                alternarBotonFormulario("Guardar");
            }
        } catch (error) {
            mostrarError("Error de conexión");
            alternarBotonFormulario("Guardar");
        }
    });

    
    // Predicción de servicio/aplicación
    const inputServicio = document.getElementById('servicio_nombre');
    
    let timeoutBusqueda; // Variable para el debounce

    inputServicio.addEventListener('input', () => {
        const query = inputServicio.value.trim();
        const sugerenciasDiv = document.getElementById('sugerencias_container');
        const preview = document.getElementById('logo_preview');
        const url_service = document.getElementById('url_service');
        const url_service_input = document.getElementById('url_service_input');

        preview.style.display = "none";
        url_service.style.display = "none";
        url_service_input.value = "";
        indiceResaltado = -1;
        
        clearTimeout(timeoutBusqueda);

        if (query.length < 4) {
            if (sugerenciasDiv) {
                sugerenciasDiv.innerHTML = "";
                sugerenciasDiv.style.display = "none";
            }
            return;
        }

        timeoutBusqueda = setTimeout(async () => {
            try {
                const res = await fetch(`https://autocomplete.clearbit.com/v1/companies/suggest?query=${query}`);
                const data = await res.json();

                const empresasFiltradas = [];
                const nombresVistos = new Set();

                data.forEach(empresa => {
                    const nombreBajo = empresa.name.toLowerCase();
                    if (!nombresVistos.has(nombreBajo)) {
                        nombresVistos.add(nombreBajo);
                        empresasFiltradas.push(empresa);
                    }
                });

                if (empresasFiltradas.length === 0) {
                    sugerenciasDiv.style.display = "none";
                    return;
                }

                if (document.activeElement === inputServicio) {
                    sugerenciasDiv.style.display = "block";
                } else {
                    sugerenciasDiv.style.display = "none";
                    return;
                }

                sugerenciasDiv.innerHTML = ""; 

                empresasFiltradas.slice(0, 3).forEach(empresa => {
                    const item = document.createElement('div');
                    item.classList.add('sugerencia-item');
                    item.innerText = empresa.name;
                    
                    // Al hacer clic, se autocompleta el input y se cierra la lista
                    item.onmousedown = (e) => {
                        e.preventDefault(); 
                        
                        inputServicio.value = empresa.name;
                        inputServicio.blur();
                        sugerenciasDiv.innerHTML = "";
                        sugerenciasDiv.style.display = "none";

                        preview.src = `https://www.google.com/s2/favicons?domain=${empresa.domain}&sz=64`;
                        preview.style.display = "block";

                        url_service_input.value = empresa.domain;
                        url_service.innerText = empresa.domain;
                        url_service.style.display = "block";
                    };
                    
                    sugerenciasDiv.appendChild(item);
                });
            } catch (err) {
                console.error(err);
            }
        }, 300);
    });

    inputServicio.addEventListener('blur', () => {
        const sugerenciasDiv = document.getElementById('sugerencias_container');
        if (sugerenciasDiv) {
            sugerenciasDiv.style.display = "none";
        }
    });

    let indiceResaltado = -1;

    inputServicio.addEventListener('keydown', (e) => {
        const sugerenciasDiv = document.getElementById('sugerencias_container');
        const items = sugerenciasDiv.querySelectorAll('.sugerencia-item');
        
        if (sugerenciasDiv.style.display === "none" || items.length === 0) return;

        if (e.key === "ArrowDown") {
            e.preventDefault();
            indiceResaltado = (indiceResaltado + 1) % items.length;
            actualizarResaltado(items);
        } else if (e.key === "ArrowUp") {
            e.preventDefault();
            indiceResaltado = (indiceResaltado - 1 + items.length) % items.length;
            actualizarResaltado(items);
        } else if (e.key === "Enter" && indiceResaltado > -1) {
            e.preventDefault();
            items[indiceResaltado].onmousedown(e); // Ejecutamos la lógica de selección
        }
    });

    function actualizarResaltado(items) {
        items.forEach((item, i) => {
            item.classList.toggle('active', i === indiceResaltado);
        });
    }
}