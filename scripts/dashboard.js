let todasLasCuentas = [];
let cuentasVisibles = 0;
const LOTE_CARGA = 24;
const LOTE_RELLENO = 6;

// Obtenemos las cuentas del usuario
async function obtenerCuentasUsuario() {
    try {
        const resultado = await apiAuth("obtener_cuentas", { method: "GET" });

        if (resultado?.code === 401 || resultado?.status !== "success") {
            // logout “duro”
            setAccessToken(null);
            if (typeof setRefreshToken === "function") setRefreshToken(null);
            vault.lock();
            navegarA("login");
            return null; // <- importante: no confundas con "0 cuentas"
        }

        // descifrar en cliente
        const cuentas = await Promise.all(
        resultado.cuentas.map(async (row) => {
            const data = await vault.decryptObject(row.blob);
            return { id: row.id, ...data };
        })
        );

        cuentas.sort((a, b) => (a.servicio ?? "").localeCompare((b.servicio ?? ""), "es", { sensitivity: "base" }));

        return cuentas;
    } catch {
        return [];
    }
}

// Mostrar/ocultar la contraseña
function alternarVisibilidadPassword(el) {
    const isVisible = el.getAttribute("data-show") === "true";
    const card = el.closest('.aplicacion');
    const txtPass = card.querySelector('.txt-password');
    // Buscamos el valor real desde el atributo onclick del botón copiar de esa misma tarjeta
    const cuenta = getCuentaFromCard(el);
    const passReal = cuenta?.pass_servicio ?? "";

    const pathVisible = '<circle cx="12" cy="12" r="3.5"></circle><path d="M20.188 10.9343C20.5762 11.4056 20.7703 11.6412 20.7703 12C20.7703 12.3588 20.5762 12.5944 20.188 13.0657C18.7679 14.7899 15.6357 18 12 18C8.36427 18 5.23206 14.7899 3.81197 13.0657C3.42381 12.5944 3.22973 12.3588 3.22973 12C3.22973 11.6412 3.42381 11.4056 3.81197 10.9343C5.23206 9.21014 8.36427 6 12 6C15.6357 6 18.7679 9.21014 20.188 10.9343Z"></path>';
    const pathHidden = '<path fill-rule="evenodd" stroke="none" clip-rule="evenodd" d="M15.9202 12.7988C15.9725 12.5407 16 12.2736 16 12C16 9.79086 14.2091 8 12 8C11.7264 8 11.4593 8.02746 11.2012 8.07977L12.1239 9.00251C13.6822 9.06583 14.9342 10.3178 14.9975 11.8761L15.9202 12.7988ZM9.39311 10.5143C9.14295 10.9523 9 11.4595 9 12C9 13.6569 10.3431 15 12 15C12.5405 15 13.0477 14.857 13.4857 14.6069L14.212 15.3332C13.5784 15.7545 12.8179 16 12 16C9.79086 16 8 14.2091 8 12C8 11.1821 8.24547 10.4216 8.66676 9.78799L9.39311 10.5143Z" fill="#ffffff"></path><path stroke="none" fill-rule="evenodd" clip-rule="evenodd" d="M16.1537 17.2751L15.4193 16.5406C14.3553 17.1196 13.1987 17.5 12 17.5C10.3282 17.5 8.73816 16.7599 7.36714 15.7735C6.00006 14.79 4.89306 13.5918 4.19792 12.7478C3.77356 12.2326 3.72974 12.1435 3.72974 12C3.72974 11.8565 3.77356 11.7674 4.19792 11.2522C4.86721 10.4396 5.9183 9.29863 7.21572 8.33704L6.50139 7.62271C5.16991 8.63072 4.10383 9.79349 3.42604 10.6164L3.36723 10.6876C3.03671 11.087 2.72974 11.4579 2.72974 12C2.72974 12.5421 3.0367 12.913 3.36723 13.3124L3.42604 13.3836C4.15099 14.2638 5.32014 15.5327 6.78312 16.5853C8.24216 17.635 10.0361 18.5 12 18.5C13.5101 18.5 14.9196 17.9886 16.1537 17.2751ZM9.18993 6.06861C10.0698 5.71828 11.0135 5.5 12 5.5C13.9639 5.5 15.7579 6.365 17.2169 7.41472C18.6799 8.46727 19.849 9.73623 20.574 10.6164L20.6328 10.6876C20.9633 11.087 21.2703 11.4579 21.2703 12C21.2703 12.5421 20.9633 12.913 20.6328 13.3124L20.574 13.3836C20.0935 13.9669 19.418 14.721 18.5911 15.4697L17.883 14.7617C18.6787 14.0456 19.3338 13.3164 19.8021 12.7478C20.2265 12.2326 20.2703 12.1435 20.2703 12C20.2703 11.8565 20.2265 11.7674 19.8021 11.2522C19.107 10.4082 18 9.21001 16.6329 8.22646C15.2619 7.24007 13.6718 6.5 12 6.5C11.3056 6.5 10.6253 6.62768 9.96897 6.84765L9.18993 6.06861Z" fill="#ffffff"></path><path d="M5 2L21 18" stroke="#ffffff"></path>';

    // Alternar visualización
    if (isVisible) {
        el.innerHTML = pathVisible;
        txtPass.innerText = "******";
        el.setAttribute("data-show", "false");
    } else {
        el.innerHTML = pathHidden;
        txtPass.innerText = passReal;
        el.setAttribute("data-show", "true");
    }
}

function escapeHtml(text) {
    if (!text) return text;
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Función auxiliar para renderizar HTML (No la llames directamente, la usan las otras funciones)
function renderizarCuentas(lista, limpiar = false) {
    const contenedor = document.getElementById("contenedor_cuentas");
    if (!contenedor) return;

    if (limpiar) contenedor.innerHTML = "";

    let htmlBuffer = ""; // Creamos un string gigante para insertarlo de una sola vez (más rápido)

    lista.forEach(cuenta => {
        const nombreBase = (cuenta.url_servicio || cuenta.servicio || "").toLowerCase().replace(/\s/g, '');
        const dominio = nombreBase.includes('.') ? nombreBase : `${nombreBase}.com`;
        
        htmlBuffer += `
            <div class="aplicacion columna" data-id="${cuenta.id}">
                <span class="load-page disabled">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200"><radialGradient id="a11" cx=".66" fx=".66" cy=".3125" fy=".3125" gradientTransform="scale(1.5)"><stop offset="0" stop-color="#FFFFFF"></stop><stop offset=".3" stop-color="#FFFFFF" stop-opacity=".9"></stop><stop offset=".6" stop-color="#FFFFFF" stop-opacity=".6"></stop><stop offset=".8" stop-color="#FFFFFF" stop-opacity=".3"></stop><stop offset="1" stop-color="#FFFFFF" stop-opacity="0"></stop></radialGradient><circle transform-origin="center" fill="none" stroke="url(#a11)" stroke-width="23" stroke-linecap="round" stroke-dasharray="200 1000" stroke-dashoffset="0" cx="100" cy="100" r="70"><animateTransform type="rotate" attributeName="transform" calcMode="spline" dur="2" values="360;0" keyTimes="0;1" keySplines="0 0 1 1" repeatCount="indefinite"></animateTransform></circle><circle transform-origin="center" fill="none" opacity=".2" stroke="#FFFFFF" stroke-width="23" stroke-linecap="round" cx="100" cy="100" r="70"></circle></svg>
                </span>
                <div class="fila" style="width: 100%;justify-content: space-between; align-items: start;">
                    <div class="fila app-title">
                        <img src="https://www.google.com/s2/favicons?domain=${escapeHtml(dominio)}&sz=64" loading="lazy">
                        <p class="subtitulo" style="color: white;">${escapeHtml(cuenta.servicio)}</p>
                    </div>
                    <div class="fila">
                        <svg onclick="alternarVisibilidadPassword(this)" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <circle cx="12" cy="12" r="3.5"></circle> <path d="M20.188 10.9343C20.5762 11.4056 20.7703 11.6412 20.7703 12C20.7703 12.3588 20.5762 12.5944 20.188 13.0657C18.7679 14.7899 15.6357 18 12 18C8.36427 18 5.23206 14.7899 3.81197 13.0657C3.42381 12.5944 3.22973 12.3588 3.22973 12C3.22973 11.6412 3.42381 11.4056 3.81197 10.9343C5.23206 9.21014 8.36427 6 12 6C15.6357 6 18.7679 9.21014 20.188 10.9343Z"></path> </g></svg>
                        <svg onclick="copiarPass(this)" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" stroke-width="1.056"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path d="M15 3H9C6.79086 3 5 4.79086 5 7V15"></path> <path d="M8.5 11.5C8.5 10.3156 8.50074 9.46912 8.57435 8.81625C8.64681 8.17346 8.78457 7.78051 9.01662 7.4781C9.14962 7.30477 9.30477 7.14962 9.4781 7.01662C9.78051 6.78457 10.1735 6.64681 10.8163 6.57435C11.4691 6.50074 12.3156 6.5 13.5 6.5C14.6844 6.5 15.5309 6.50074 16.1837 6.57435C16.8265 6.64681 17.2195 6.78457 17.5219 7.01662C17.6952 7.14962 17.8504 7.30477 17.9834 7.4781C18.2154 7.78051 18.3532 8.17346 18.4257 8.81625C18.4993 9.46912 18.5 10.3156 18.5 11.5V15.5C18.5 16.6844 18.4993 17.5309 18.4257 18.1837C18.3532 18.8265 18.2154 19.2195 17.9834 19.5219C17.8504 19.6952 17.6952 19.8504 17.5219 19.9834C17.2195 20.2154 16.8265 20.3532 16.1837 20.4257C15.5309 20.4993 14.6844 20.5 13.5 20.5C12.3156 20.5 11.4691 20.4993 10.8163 20.4257C10.1735 20.3532 9.78051 20.2154 9.4781 19.9834C9.30477 19.8504 9.14962 19.6952 9.01662 19.5219C8.78457 19.2195 8.64681 18.8265 8.57435 18.1837C8.50074 17.5309 8.5 16.6844 8.5 15.5V11.5Z"></path> </g></svg>
                        <svg onclick="eliminarCuenta(${escapeHtml(cuenta.id)}, this)" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path d="M3 6H21M5 6V20C5 21.1046 5.89543 22 7 22H17C18.1046 22 19 21.1046 19 20V6M8 6V4C8 2.89543 8.89543 2 10 2H14C15.1046 2 16 2.89543 16 4V6" stroke-width="0.9600000000000002" stroke-linecap="round" stroke-linejoin="round"></path> <path d="M14 11V17" stroke-width="0.9600000000000002" stroke-linecap="round" stroke-linejoin="round"></path> <path d="M10 11V17" stroke-width="0.9600000000000002" stroke-linecap="round" stroke-linejoin="round"></path> </g></svg>
                        <svg onclick="editarCuentaServicio(${escapeHtml(cuenta.id)})" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path d="M5.92971 19.283L5.92972 19.283L5.95149 19.2775L5.95151 19.2775L8.58384 18.6194C8.59896 18.6156 8.61396 18.6119 8.62885 18.6082C8.85159 18.5528 9.04877 18.5037 9.2278 18.4023C9.40683 18.301 9.55035 18.1571 9.71248 17.9947C9.72332 17.9838 9.73425 17.9729 9.74527 17.9618L16.9393 10.7678L16.9393 10.7678L16.9626 10.7445C17.2761 10.4311 17.5461 10.1611 17.7333 9.91573C17.9339 9.65281 18.0858 9.36038 18.0858 9C18.0858 8.63961 17.9339 8.34719 17.7333 8.08427C17.5461 7.83894 17.276 7.5689 16.9626 7.2555L16.9393 7.23223L16.5858 7.58579L16.9393 7.23223L16.7678 7.06066L16.7445 7.03738C16.4311 6.72395 16.1611 6.45388 15.9157 6.2667C15.6528 6.0661 15.3604 5.91421 15 5.91421C14.6396 5.91421 14.3472 6.0661 14.0843 6.2667C13.8389 6.45388 13.5689 6.72395 13.2555 7.03739L13.2322 7.06066L6.03816 14.2547C6.02714 14.2658 6.01619 14.2767 6.00533 14.2875C5.84286 14.4496 5.69903 14.5932 5.59766 14.7722C5.4963 14.9512 5.44723 15.1484 5.39179 15.3711C5.38809 15.386 5.38435 15.401 5.38057 15.4162L4.71704 18.0703C4.71483 18.0791 4.7126 18.088 4.71036 18.097C4.67112 18.2537 4.62921 18.421 4.61546 18.5615C4.60032 18.7163 4.60385 18.9773 4.81326 19.1867C5.02267 19.3961 5.28373 19.3997 5.43846 19.3845C5.57899 19.3708 5.74633 19.3289 5.90301 19.2896C5.91195 19.2874 5.92085 19.2852 5.92971 19.283Z"></path> <path d="M12.5 7.5L15.5 5.5L18.5 8.5L16.5 11.5L12.5 7.5Z"></path> </g></svg>
                    </div>
                </div>
                <div class="fila" style="width: 100%;">
                    <div class="columna">
                        <p class="anotacion">${escapeHtml(cuenta.email_servicio)}</p>
                        <p class="anotacion txt-password">******</p>
                    </div>
                </div>
            </div>
        `;
    });

    contenedor.insertAdjacentHTML('beforeend', htmlBuffer);
}

function renderNextBatch(take = LOTE_CARGA) {
    if (cuentasVisibles >= todasLasCuentas.length) return false;

    const lote = todasLasCuentas.slice(cuentasVisibles, cuentasVisibles + take);
    renderizarCuentas(lote, false);
    cuentasVisibles += lote.length;

    return lote.length > 0;
}

function hasScrollableOverflow(container) {
    return container.scrollHeight > container.clientHeight + 2; // +2 por redondeos
}

// Renderiza páginas hasta que haya scroll o no queden items
function fillViewport(container, renderNextBatch) {
    let safety = 0;

    // Renderiza tandas hasta que haya overflow o no queden cuentas
    while (!hasScrollableOverflow(container) && safety < 50) {
        const rendered = renderNextBatch();
        if (!rendered) break; // no había más para renderizar
        safety++;
    }
}

async function cargarCuentasEnPantalla() {
    const loader = document.getElementById("load_page");
    const container = document.getElementById('page-container');
    const contenedorCuentas = document.getElementById("contenedor_cuentas");

    if (!contenedorCuentas) return;

    try {
        const listaCuentas = await obtenerCuentasUsuario();
        if (listaCuentas === null) return; // ya redirigió a login

        if (listaCuentas.length === 0) {
            navegarA('dashboard-empty');
            return;
        }

        todasLasCuentas = listaCuentas;
        cuentasVisibles = 0;

        // Render inicial
        const primerLote = todasLasCuentas.slice(0, LOTE_CARGA);
        renderizarCuentas(primerLote, true);
        cuentasVisibles = primerLote.length;

        fillViewport(contenedorCuentas, () => renderNextBatch(LOTE_RELLENO));
    } catch (error) {
        contenedorCuentas.innerHTML = "<p class='anotacion'>Error al cargar datos.</p>";
    } finally {
        if (loader) loader.classList.add("disabled");
        if (container) container.style.opacity = "1"; // Encendemos el contenedor que inyectamos
    }
}

// Funcion para eliminar cuenta
async function eliminarCuenta(id, eliminarButton) {
    const confirmacion = await mostrarConfirmacionCustom("¿Estás seguro de que quieres eliminar esta cuenta?");
    
    if (!confirmacion) return;

    eliminarButton.closest(".aplicacion").querySelector(".load-page").classList.remove("disabled");

    try {
        const res = await apiAuth('eliminar_servicio', {
            method: 'POST',
            body: { id: id }
        });

        if (res.status === "success") {
            cargarCuentasEnPantalla();
        } else {
            alert("Error: " + res.message);
        }
    } catch (error) {
        console.error("Error al eliminar:", error);
    }
}

// Funcion para copiar la contraseña
function copiarAlPortapapeles(texto, button) {
    navigator.clipboard.writeText(texto).then(() => {
        button.classList.add("copied");
        setTimeout(() => { button.classList.remove("copied") }, 150);
    });
}

function getCuentaFromCard(el) {
    const card = el.closest(".aplicacion");
    if (!card?.dataset?.id) return null;
    const id = Number(card.dataset.id);
    return todasLasCuentas.find(c => Number(c.id) === id) || null;
}

function copiarPass(button) {
    const cuenta = getCuentaFromCard(button);
    if (!cuenta) return;
    copiarAlPortapapeles(cuenta.pass_servicio ?? "", button);
}

function prepararVistaDashboard() {
    // 1. Verificar sesión sin recargar
    if (!getAccessToken() || !vault.isUnlocked()) {
        navegarA("login");
        return;
    }

    // 2. Cargar tarjetas
    cargarCuentasEnPantalla();

    const searchInput = document.getElementById("search_input");
    const contenedorMain = document.getElementById("contenedor_cuentas"); // Asegúrate de que este es el elemento que tiene el scroll

    // 3. Evento: BUSCADOR (Sobre memoria, no sobre DOM)
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            const term = e.target.value.toLowerCase().trim();

            if (term === "") {
                // Restaurar vista paginada si borra
                cuentasVisibles = 0;
                const primerLote = todasLasCuentas.slice(0, LOTE_CARGA);
                renderizarCuentas(primerLote, true);
                cuentasVisibles = primerLote.length;

                fillViewport(contenedorMain, renderNextBatch);
            } else {
                // Filtrar array global y renderizar todo lo que coincida
                const filtradas = todasLasCuentas.filter(cuenta => 
                    (cuenta.servicio || "").toLowerCase().startsWith(term)
                );
                renderizarCuentas(filtradas, true);
            }
        });
    }

    // 4. Evento: SCROLL INFINITO
    if (contenedorMain) {
        contenedorMain.addEventListener('scroll', () => {
            // Solo cargamos más si NO hay búsqueda activa
            if (searchInput && searchInput.value.trim() !== "") return;

            // Detectar si llegamos al final del scroll
            if (contenedorMain.scrollTop + contenedorMain.clientHeight >= contenedorMain.scrollHeight - 100) {
                renderNextBatch(LOTE_CARGA); // lote grande por scroll real
                fillViewport(contenedorMain, () => renderNextBatch(LOTE_RELLENO)); // ajuste fino
            }
        });
    }

    window.addEventListener('resize', () => {
        if (searchInput && searchInput.value.trim() !== "") return;

        const contenedorMain = document.getElementById("contenedor_cuentas");
        if (!contenedorMain) return;

        fillViewport(contenedorMain, () => renderNextBatch(LOTE_RELLENO));
    });
}