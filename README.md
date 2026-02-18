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

## 📦 Descargar e instalar (Usuarios)

En **Releases** vas a encontrar dos builds:

- ✅ **Instalador (recomendado):** `PassManager-Setup-x.y.z.exe`  
  - Se instala como cualquier app de Windows  
  - **Incluye auto-actualizaciones** (cuando hay nuevas versiones)
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
- **Aislamiento del renderer (Electron):** configuración orientada a reducir superficie de ataque (contextIsolation, sin Node en renderer, sandbox).
- **Autorización por usuario en API:** las rutas que operan sobre cuentas validan identidad y propiedad del recurso.

> Nota: este README describe el enfoque general. Los detalles finos de implementación se mantienen en el código.

---

## 🧱 Stack

- **Desktop:** Electron + HTML/CSS/JS
- **Backend:** PHP (API HTTP)
- **DB:** Postgres (Supabase)
- **Hosting backend:** Render

---
