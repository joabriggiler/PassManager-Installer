# PassManager

PassManager es una aplicación de escritorio (Electron) para **guardar y administrar credenciales** (servicio, email y contraseña) con foco en **privacidad** y **seguridad por diseño**.

> **Idea clave:** los datos se cifran **antes de salir del dispositivo**. El backend solo almacena **blobs cifrados** y aplica controles de autenticación/autorización.

---

## ✨ Funcionalidades

- Guardar cuentas (servicio, email, contraseña, URL)
- Listado con búsqueda
- Copiar contraseña al portapapeles
- Editar / eliminar servicios
- Sesión con renovación automática (tokens)

---

## 🕵️ Privacidad

- **Sin telemetría / analytics:** la app **no integra SDKs de tracking** (Sentry/PostHog/Segment/Mixpanel/Amplitude/etc.).
- **Sin anuncios.**
- **Datos cifrados end-to-end:** el servidor no puede leer tus credenciales sin tu contraseña maestra.

> Nota: esto no reemplaza una auditoría externa. Si encontrás un problema de seguridad, ver “Reporte de seguridad”.

---

## 🌐 Conectividad (qué servidores toca la app)

PassManager realiza conexiones de red únicamente para:

1. **API de PassManager** (login/sync): `https://passmanager-api.onrender.com` :contentReference[oaicite:0]{index=0}  
2. **Autocompletado opcional de servicios (Clearbit):** `https://autocomplete.clearbit.com` :contentReference[oaicite:1]{index=1}  
3. **Auto-actualizaciones (solo instalador):** consulta releases/publicación en **GitHub** vía `electron-updater` :contentReference[oaicite:2]{index=2}

---

## 📦 Descargar e instalar (Usuarios)

En **Releases** vas a encontrar dos builds:

- ✅ **Instalador (recomendado):** `PassManager-Setup-x.y.z.exe`  
  - Se instala como cualquier app de Windows  
  - **Incluye auto-actualizaciones**
- ⚪ **Portable:** `PassManager-x.y.z.exe`  
  - No requiere instalación  
  - Puede no ser ideal para actualizaciones

> **No necesitás instalar Node.js** para usar PassManager. Solo es necesario para desarrollo.

### SmartScreen de Windows
Al no estar firmada con un certificado comercial, Windows puede mostrar una advertencia (“Editor desconocido”).  
Si descargaste el instalador desde **Releases** de este repositorio, podés continuar con **“Más información” → “Ejecutar de todas formas”**.

---

## 🔐 Seguridad (alto nivel)

Este repositorio implementa medidas para reducir riesgos comunes, sin exponer detalles innecesarios:

- **Cifrado en cliente (Vault):** la app cifra/descifra localmente y sube al servidor únicamente un `blob` cifrado.
- **Claves derivadas desde contraseña:** la clave de la bóveda se deriva localmente usando un KDF con parámetros fuertes.
- **Autenticación sin enviar la contraseña:** el login no transmite la contraseña en texto plano al servidor.
- **Sesiones con tokens:** el backend emite tokens de acceso de corta duración y un mecanismo de renovación.
- **Aislamiento del renderer (Electron):** configuración orientada a reducir superficie de ataque.
- **Política CSP en la UI:** se limita la carga/conexión a orígenes específicos :contentReference[oaicite:3]{index=3}
- **Empaquetado:** ASAR habilitado y compresión máxima para distribución :contentReference[oaicite:4]{index=4}

### Limitaciones (amenazas fuera de alcance)
- Si tu equipo está comprometido (malware/keylogger), ninguna app de passwords puede garantizar protección total.
- Si olvidás la contraseña maestra, **no hay recuperación** del vault (por diseño).

---

## 🧱 Stack

- **Desktop:** Electron + HTML/CSS/JS
- **Backend:** PHP (API HTTP)
- **DB:** Postgres (Supabase)
- **Hosting backend:** Render

---

## 🧑‍💻 Desarrollo

Requisitos: Node.js (solo para dev)

```bash
npm install
npm run start
```

Build local:

```bash
npm run pack     # build en carpeta (sin instalador)
npm run dist     # genera instalador y portable
```
Scripts y targets (NSIS + portable)

---

## 🛡️ Reporte de seguridad

Si encontrás una vulnerabilidad, por favor abrí un issue solo si no expone datos sensibles.
Para reportes privados, contactame por el medio que figure en mi perfil de GitHub.

