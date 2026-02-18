const KDF_DEFAULT_ITERS = 310000; // podés ajustar
// Alias para mantener tu código nuevo tal cual
async function encriptarBlob(obj) {
  // si te llega string JSON, lo convertimos a objeto
  if (typeof obj === "string") obj = JSON.parse(obj);
  return await vault.encryptObject(obj);
}

async function desencriptarBlob(blobStr) {
  return await vault.decryptObject(blobStr); // devuelve OBJETO ya parseado
}


function bytesToB64(bytes) {
    let bin = "";
    bytes.forEach(b => bin += String.fromCharCode(b));
    return btoa(bin);
}
function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function generarSaltB64() {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    return bytesToB64(salt);
}

const vault = (() => {
    let encKey = null;

    return {
        isUnlocked: () => !!encKey,
        unlock: (k) => { encKey = k; },
        lock: () => { encKey = null; },

        async deriveFromPassword(masterPassword, saltB64, iterations) {
        const salt = b64ToBytes(saltB64);
        const iters = iterations ?? KDF_DEFAULT_ITERS;

        const passKey = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(masterPassword),
            "PBKDF2",
            false,
            ["deriveBits"]
        );

        // 64 bytes: 32 para AES key + 32 para auth key
        const bits = await crypto.subtle.deriveBits(
            { name: "PBKDF2", hash: "SHA-256", salt, iterations: iters },
            passKey,
            512
        );

        const raw = new Uint8Array(bits);
        const encKeyBytes = raw.slice(0, 32);
        const authKeyBytes = raw.slice(32);

        const k = await crypto.subtle.importKey(
            "raw",
            encKeyBytes,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        const authDigest = await crypto.subtle.digest("SHA-256", authKeyBytes);
        const authVerifierB64 = bytesToB64(new Uint8Array(authDigest));

        // best-effort zeroize
        raw.fill(0); encKeyBytes.fill(0); authKeyBytes.fill(0);

        return { encKey: k, authVerifierB64, iterations: iters };
        },

        async encryptObject(obj) {
        if (!encKey) throw new Error("Vault bloqueada.");
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const pt = new TextEncoder().encode(JSON.stringify(obj));
        const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encKey, pt);
        return JSON.stringify({
            v: 1,
            iv: bytesToB64(iv),
            ct: bytesToB64(new Uint8Array(ctBuf)),
        });
        },

        async decryptObject(blobStr) {
        if (!encKey) throw new Error("Vault bloqueada.");
        const blob = JSON.parse(blobStr);
        if (!blob || blob.v !== 1) throw new Error("Blob inválido.");
        const iv = b64ToBytes(blob.iv);
        const ct = b64ToBytes(blob.ct);
        const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, encKey, ct);
        return JSON.parse(new TextDecoder().decode(ptBuf));
        },
    };
})();


const API_BASE = 'https://passmanager-api.onrender.com/api.php';

// Guardá el access token en memoria (mejor que localStorage)
// Persistimos el access token (para que no se pierda entre vistas / recargas)
const ACCESS_TOKEN_KEY = 'pm_access_token';

function setAccessToken(t) {
    if (t) sessionStorage.setItem(ACCESS_TOKEN_KEY, t);
    else sessionStorage.removeItem(ACCESS_TOKEN_KEY);
}
function getAccessToken() {
    return sessionStorage.getItem(ACCESS_TOKEN_KEY);
}


const REFRESH_TOKEN_KEY = "pm_refresh_token";

function setRefreshToken(t) {
    if (t) localStorage.setItem(REFRESH_TOKEN_KEY, t);
    else localStorage.removeItem(REFRESH_TOKEN_KEY);
}
function getRefreshToken() {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
}

// 1) Refresh: backend devuelve { status:'success', access_token:'...' } y setea/lee cookie HttpOnly del refresh
async function refreshAccessToken() {
    const rt = getRefreshToken();
    if (!rt) return false;

    const res = await fetch(`${API_BASE}?accion=refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: rt })
    });

    const data = await res.json();
    if (data.status === 'success' && data.access_token) {
        setAccessToken(data.access_token);
        setRefreshToken(data.refresh_token); // rotación
        return true;
    }

    setAccessToken(null);
    setRefreshToken(null);
    return false;
}

// 2) Fetch autenticado + reintento con refresh si hay 401
async function apiAuth(accion, { method = 'POST', body = null, query = null } = {}) {
    const url = new URL(API_BASE);
    url.searchParams.set('accion', accion);
    if (query) for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);

    const doFetch = async () => {
        const headers = {};
        if (body) headers['Content-Type'] = 'application/json';

        const token = getAccessToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
            headers['X-Auth-Token'] = token; // 👈 clave para hosts que “pierden” Authorization
        }

        const res = await fetch(url.toString(), {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined
        });

        return { res, data: await res.json().catch(() => ({})) };
    };

    let { res, data } = await doFetch();

    if (res.status === 401) {
        const ok = await refreshAccessToken();
        if (!ok) return { status: 'error', code: 401, message: 'Sesión expirada. Iniciá sesión nuevamente.' };
        ({ res, data } = await doFetch());
    }

    return data;
}

// Control de ventana (Barra superior)
document.getElementById('minimize_app').addEventListener('click', () => window.pm.window.minimize());
document.getElementById('maximize_app').addEventListener('click', () => window.pm.window.maximize());
document.getElementById('close_app').addEventListener('click', () => window.pm.window.close());

// MOTOR DE NAVEGACIÓN
async function navegarA(pagina) {
    const main      = document.getElementById('main-content');
    const container = document.getElementById('page-container'); // Inyectamos aquí
    const loader    = document.getElementById('load_page');
    const timeoutMsg = document.getElementById('load-timeout-msg');

    loader?.classList.remove('disabled');
    container.style.opacity = "0";
    if (timeoutMsg) timeoutMsg.style.display = "none";

    const cargaLentaTimer = setTimeout(() => {
        if (timeoutMsg && loader && !loader.classList.contains('disabled')) {
        timeoutMsg.style.display = "block";
        }
    }, 5000);

    try {
        await new Promise(r => setTimeout(r, 250));

        let paginaAServir = pagina;

        if (pagina === 'dashboard') {
            // Si no hay token o la vault no está desbloqueada, no tiene sentido entrar al dashboard
            if (!getAccessToken() || !vault.isUnlocked()) {
                paginaAServir = 'login';
            } else {
                const r = await apiAuth("obtener_cuentas", { method: "GET" });

                // Sesión expirada / no autorizado → login directo
                if (r?.code === 401 || r?.status !== "success") {
                paginaAServir = 'login';
                } else if ((r.cuentas || []).length === 0) {
                paginaAServir = 'dashboard-empty';
                }
            }
        }

        const response = await fetch(`./${paginaAServir}.html`);
        if (!response.ok) throw new Error("No se pudo cargar la vista");
        
        const html = await response.text();

        Array.from(main.classList).forEach(cls => {
            if (cls.startsWith('vista-')) main.classList.remove(cls);
        });
        main.classList.add(`vista-${paginaAServir}`);

        container.innerHTML = html; 
        
        // Inicialización de vistas
        if (paginaAServir === 'dashboard') {
            prepararVistaDashboard();
        } else {
            if (paginaAServir === 'login') prepararVistaLogin();
            if (paginaAServir === 'register') prepararVistaRegister();
            if (paginaAServir === 'new-service') prepararVistaNewService();
            if (paginaAServir === 'edit-service') {
                const idGuardado = localStorage.getItem("edit_cuenta_id");
                await prepararVistaEditService(idGuardado);
            }
        }

        container.style.opacity = "1";
        loader?.classList.add('disabled');
    } catch (err) {
        loader?.classList.add('disabled');
        container.style.opacity = "1";
        const destinoRedir = getAccessToken() ? 'dashboard' : 'login';
        container.innerHTML = `
            <p class="anotacion">
            Error al cargar la página. 
            <a href="#" onclick="navegarA('${destinoRedir}')">Reintentar</a>
            </p>`;
    } finally {
        clearTimeout(cargaLentaTimer);
        if (timeoutMsg) timeoutMsg.style.display = "none";
    }
}

// 1. Registro de usuario en PassManager
async function registrarUsuario(email, masterPassword) {
    const kdf_salt_b64 = generarSaltB64();
    const { authVerifierB64, iterations } = await vault.deriveFromPassword(masterPassword, kdf_salt_b64, KDF_DEFAULT_ITERS);

    const url = `${API_BASE}?accion=registro`;
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
        email,
        kdf_salt_b64,
        kdf_iter: iterations,
        auth_verifier: authVerifierB64,
        }),
    });

    // best-effort: soltar referencia
    masterPassword = null;

    return await response.json();
}

//2. Inicio de sesión de usuario en PassManager
let usuarioIdActual = null;

async function loginUsuario(email, masterPassword) {
    // 1) pedir salt + iters
    const pre = await fetch(`${API_BASE}?accion=prelogin`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
    });
    const preData = await pre.json();
    if (preData.status !== "success") return preData;

    // 2) derivar keys localmente
    const { encKey, authVerifierB64 } = await vault.deriveFromPassword(
        masterPassword,
        preData.kdf_salt_b64,
        preData.kdf_iter
    );

    // 3) login enviando SOLO auth_verifier
    const response = await fetch(`${API_BASE}?accion=login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, auth_verifier: authVerifierB64 }),
    });

    const data = await response.json();

    if (data.status === "success") {
        setAccessToken(data.access_token);
        setRefreshToken(data.refresh_token);
        vault.unlock(encKey); // 🔥 llave en RAM
    } else {
        vault.lock();
    }

    masterPassword = null;
    return data;
}
async function cerrarSesion(e) {
    if (e) e.preventDefault();

    const confirmar = await mostrarConfirmacionCustom("¿Estás seguro de que deseas cerrar sesión?");
    if (!confirmar) return;

    await apiAuth('logout', { method: 'POST' });
    setAccessToken(null);
    setRefreshToken(null);
    
    localStorage.clear();
    vault.lock();

    navegarA('login');
}
function mostrarOcultarPassword(svgElement){
    const input = svgElement.closest(".input").querySelector("input");
    const input2 = document.getElementById("password-repeat");
    const pathVisible = '<circle cx="12" cy="12" r="3.5"></circle><path d="M20.188 10.9343C20.5762 11.4056 20.7703 11.6412 20.7703 12C20.7703 12.3588 20.5762 12.5944 20.188 13.0657C18.7679 14.7899 15.6357 18 12 18C8.36427 18 5.23206 14.7899 3.81197 13.0657C3.42381 12.5944 3.22973 12.3588 3.22973 12C3.22973 11.6412 3.42381 11.4056 3.81197 10.9343C5.23206 9.21014 8.36427 6 12 6C15.6357 6 18.7679 9.21014 20.188 10.9343Z"></path>';
    const pathHidden = '<path fill-rule="evenodd" stroke="none" clip-rule="evenodd" d="M15.9202 12.7988C15.9725 12.5407 16 12.2736 16 12C16 9.79086 14.2091 8 12 8C11.7264 8 11.4593 8.02746 11.2012 8.07977L12.1239 9.00251C13.6822 9.06583 14.9342 10.3178 14.9975 11.8761L15.9202 12.7988ZM9.39311 10.5143C9.14295 10.9523 9 11.4595 9 12C9 13.6569 10.3431 15 12 15C12.5405 15 13.0477 14.857 13.4857 14.6069L14.212 15.3332C13.5784 15.7545 12.8179 16 12 16C9.79086 16 8 14.2091 8 12C8 11.1821 8.24547 10.4216 8.66676 9.78799L9.39311 10.5143Z" fill="#ffffff"></path><path stroke="none" fill-rule="evenodd" clip-rule="evenodd" d="M16.1537 17.2751L15.4193 16.5406C14.3553 17.1196 13.1987 17.5 12 17.5C10.3282 17.5 8.73816 16.7599 7.36714 15.7735C6.00006 14.79 4.89306 13.5918 4.19792 12.7478C3.77356 12.2326 3.72974 12.1435 3.72974 12C3.72974 11.8565 3.77356 11.7674 4.19792 11.2522C4.86721 10.4396 5.9183 9.29863 7.21572 8.33704L6.50139 7.62271C5.16991 8.63072 4.10383 9.79349 3.42604 10.6164L3.36723 10.6876C3.03671 11.087 2.72974 11.4579 2.72974 12C2.72974 12.5421 3.0367 12.913 3.36723 13.3124L3.42604 13.3836C4.15099 14.2638 5.32014 15.5327 6.78312 16.5853C8.24216 17.635 10.0361 18.5 12 18.5C13.5101 18.5 14.9196 17.9886 16.1537 17.2751ZM9.18993 6.06861C10.0698 5.71828 11.0135 5.5 12 5.5C13.9639 5.5 15.7579 6.365 17.2169 7.41472C18.6799 8.46727 19.849 9.73623 20.574 10.6164L20.6328 10.6876C20.9633 11.087 21.2703 11.4579 21.2703 12C21.2703 12.5421 20.9633 12.913 20.6328 13.3124L20.574 13.3836C20.0935 13.9669 19.418 14.721 18.5911 15.4697L17.883 14.7617C18.6787 14.0456 19.3338 13.3164 19.8021 12.7478C20.2265 12.2326 20.2703 12.1435 20.2703 12C20.2703 11.8565 20.2265 11.7674 19.8021 11.2522C19.107 10.4082 18 9.21001 16.6329 8.22646C15.2619 7.24007 13.6718 6.5 12 6.5C11.3056 6.5 10.6253 6.62768 9.96897 6.84765L9.18993 6.06861Z" fill="#ffffff"></path><path d="M5 2L21 18" stroke="#ffffff"></path>';

    input.type = input.type === 'password' ? 'text' : 'password';
    svgElement.innerHTML = input.type === 'password' ? pathVisible : pathHidden;

    if(input2) input2.type = input2.type === 'password' ? 'text' : 'password';
}

//3. Añadir cuenta de servicio a PassManager
async function guardarCuentaServicio(servicio, emailServicio, passServicio, urlServicio) {
    if (!vault.isUnlocked()) {
        return { status: "error", message: "Vault bloqueada. Iniciá sesión nuevamente." };
    }

    const blob = await vault.encryptObject({
        servicio,
        email_servicio: emailServicio,
        pass_servicio: passServicio,
        url_servicio: urlServicio,
    });

    return await apiAuth("guardar_servicio", {
        method: "POST",
        body: { blob },
    });
}

// Función para mostrar errores en el HTML
function mostrarError(mensaje, inputElement = null, esAdvertencia = false) {
    document.querySelectorAll(".message_error_input").forEach(el => el.remove());

    if (inputElement) inputElement.classList.remove("different-password"); 

    if (!mensaje || !inputElement) return;

    if (esAdvertencia) inputElement.classList.add("different-password");

    const pError = document.createElement("p");
    pError.className = "message_error_input";
    
    if (esAdvertencia) pError.classList.add("warning-yellow");

    pError.innerText = mensaje;

    const contenedorInput = inputElement.closest(".input");
    if (contenedorInput) contenedorInput.after(pError);
}

//Alternar boton de formulario
function alternarBotonFormulario(texto = 'Entrar') {
    const log_button = document.getElementById("submit_button");
    if(log_button.disabled){
        log_button.disabled = false;
        log_button.innerHTML = texto; // Usa el texto que necesites
    } else {
        log_button.disabled = true;
        log_button.innerHTML = '<svg style="width: 20px;" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200"><radialGradient id="a11" cx=".66" fx=".66" cy=".3125" fy=".3125" gradientTransform="scale(1.5)"><stop offset="0" stop-color="#FFFFFF"></stop><stop offset=".3" stop-color="#FFFFFF" stop-opacity=".9"></stop><stop offset=".6" stop-color="#FFFFFF" stop-opacity=".6"></stop><stop offset=".8" stop-color="#FFFFFF" stop-opacity=".3"></stop><stop offset="1" stop-color="#FFFFFF" stop-opacity="0"></stop></radialGradient><circle transform-origin="center" fill="none" stroke="url(#a11)" stroke-width="23" stroke-linecap="round" stroke-dasharray="200 1000" stroke-dashoffset="0" cx="100" cy="100" r="70"><animateTransform type="rotate" attributeName="transform" calcMode="spline" dur="2" values="360;0" keyTimes="0;1" keySplines="0 0 1 1" repeatCount="indefinite"></animateTransform></circle><circle transform-origin="center" fill="none" opacity=".2" stroke="#FFFFFF" stroke-width="23" stroke-linecap="round" cx="100" cy="100" r="70"></circle></svg>';
    }
}

// Inicio de la App
async function inicializarApp() {
    const loader = document.getElementById('load_page');
    const timeoutMsg = document.getElementById('load-timeout-msg');

    // asegurar estado inicial
    loader?.classList.remove('disabled');
    if (timeoutMsg) timeoutMsg.style.display = "none";

    const t = setTimeout(() => {
        if (timeoutMsg && loader && !loader.classList.contains('disabled')) {
        timeoutMsg.style.display = "block";
        }
    }, 5000);

    const ok = await refreshAccessToken();

    clearTimeout(t);
    if (timeoutMsg) timeoutMsg.style.display = "none";

    if (ok) navegarA('dashboard');
    else navegarA('login');
}

// Ejecutar cuando el DOM esté listo
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inicializarApp);
} else {
    inicializarApp();
}

function mostrarConfirmacionCustom(mensaje, cancelOption = true) {
    const opacador = document.querySelector('.opacador');
    const txtMensaje = opacador.querySelector('.alert-body p');
    
    // Seteamos el mensaje dinámico
    txtMensaje.innerText = mensaje;
    opacador.classList.add("enabled");

    return new Promise((resolve) => {
        const btnAceptar = document.getElementById('alert_aceptar');
        const btnCancelar = document.getElementById('alert_cancelar');
        const btnCerrar = document.getElementById('close_alert');

        if(!cancelOption) btnCancelar.style.display = "none";

        function finalizar(valor) {
            opacador.classList.remove("enabled");
            // Limpiamos los eventos para que no se acumulen
            btnAceptar.onclick = null;
            btnCancelar.onclick = null;
            btnCerrar.onclick = null;
            resolve(valor);
        }

        btnAceptar.onclick = () => finalizar(true);
        btnCancelar.onclick = () => finalizar(false);
        btnCerrar.onclick = () => finalizar(false);
    });
}

//Modificado de cuentas alojadas en PassManager
async function obtenerDatosCuenta(id){
    if (!id) return;

    return await apiAuth('obtener_una', {
        method: 'POST',
        body: { id: id }
    });
}

async function editarCuentaServicio(id) {
    localStorage.setItem("edit_cuenta_id", id); // Guardamos el ID
    navegarA("edit-service");
}

// Guardar cambios
async function guardarCambiosServicio(idCuenta, cuentaPlana) {
    // Reemplazá encriptarBlob por TU función real de encriptado
    const blob = await encriptarBlob(cuentaPlana);

    return await apiAuth("editar_servicio", {
        method: "POST",
        body: {
        id: idCuenta,
        blob: blob
        }
    });
}

async function cuentaDesdeRow(row) {
    try {
        const data = await desencriptarBlob(row.blob); // data es OBJETO
        return { id: row.id, ...data };
    } catch (e) {
        console.error("Error al desencriptar/parsear blob:", e);
        return null;
    }
}

// Preparar pestaña
async function prepararVistaEditService(id_service) {
    if (!id_service) {
        navegarA("dashboard");
        return;
    }

    if (!vault.isUnlocked()) {
        mostrarError("Vault bloqueada. Iniciá sesión nuevamente.");
        return;
    }

    // Imprimir los datos
    const respuesta = await obtenerDatosCuenta(id_service);
    localStorage.removeItem("edit_cuenta_id");

    if (respuesta.status === "success") {
        const cuenta = await cuentaDesdeRow(respuesta.cuenta);

        if (!cuenta) {
            mostrarError("No se pudo leer la cuenta (blob inválido o corrupto).");
            return;
        }

        document.getElementById("servicio_nombre").innerText = cuenta.servicio ?? "";
        document.getElementById("email").value = cuenta.email_servicio ?? "";
        document.getElementById("password").value = cuenta.pass_servicio ?? "";

        const logo = document.getElementById("logo_preview");
        if (logo) {
            if (cuenta.url_servicio) {
            logo.src = `https://www.google.com/s2/favicons?domain=${cuenta.url_servicio}&sz=64`;
            logo.style.display = "block";
            } else {
            logo.style.display = "none";
            }
        }

        localStorage.removeItem("edit_cuenta_id");
    }

    const password_pass_input = document.getElementById("pass_password");
    if (!password_pass_input) {
        mostrarError("Falta el input de contraseña de usuario (pass_password).");
        return;
    }

    // --- LIMPIEZA DE ERRORES ---
    password_pass_input.addEventListener("input", () => {
        if(password_pass_input.classList.contains("different-password")) password_pass_input.classList.remove("different-password");
        
        const errorLabel = password_pass_input.closest(".input")?.nextElementSibling;
        if (errorLabel && errorLabel.classList.contains("message_error_input")) {
            errorLabel.remove();
        }
    });

    //Boton de Guardado de cambios
    const form = document.getElementById("edit_service_form");
    if (!form) return;

    if (form.dataset.bound === "1") return; // ya tiene listeners
    form.dataset.bound = "1";
    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        mostrarError("");
        alternarBotonFormulario();

        const emailNuevo = document.getElementById("email").value;
        const passNueva = document.getElementById("password").value;

        const email_user = localStorage.getItem("user_email");
        const password_user = password_pass_input.value;

        try {
            const resultadoLogin = await loginUsuario(email_user, password_user);
            if (resultadoLogin.status !== "success") {
            mostrarError(resultadoLogin.message, password_pass_input, true);
            alternarBotonFormulario("Guardar cambios");
            return;
            }

            // 1) Traigo la cuenta actual (row)
            const resp = await obtenerDatosCuenta(id_service);
            if (resp.status !== "success") {
            mostrarError(resp.message || "No se pudo cargar la cuenta.");
            alternarBotonFormulario("Guardar cambios");
            return;
            }

            // 2) La vuelvo “plana”
            const cuenta = await cuentaDesdeRow(resp.cuenta);

            // 3) Modifico lo editable
            cuenta.email_servicio = emailNuevo;
            cuenta.pass_servicio = passNueva;

            // 4) Guardo enviando blob
            const r = await guardarCambiosServicio(id_service, cuenta);
            if (r.status === "success") {
            navegarA("dashboard");
            } else {
            mostrarError(r.message);
            alternarBotonFormulario("Guardar cambios");
            }
        } catch (e) {
            mostrarError("Error de conexión");
            alternarBotonFormulario("Guardar cambios");
        }
    });
}

//Mostrar posible actualizacion
if (window.pm?.updater?.onReady) {
    window.pm.updater.onReady(async () => {
        const ok = await mostrarConfirmacionCustom(
        "Hay una actualización lista para instalar.\n¿Querés actualizar ahora? (La app se reiniciará)"
        );
        if (ok) window.pm.updater.install();
    });
}