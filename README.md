# 🛡️ DevSecOps Vault - Gestor de Secretos Seguro

Sistema de gestión de información confidencial desarrollado bajo la metodología **DevSecOps**, integrando seguridad desde el diseño, auditoría continua y despliegue automatizado.

![Estado de Seguridad](https://github.com/VIKO-sudo/DevSecOps-Boveda/actions/workflows/security.yml/badge.svg)

## 🚀 Características de Seguridad Implementadas

Este proyecto cumple con los estándares de seguridad OWASP y las mejores prácticas de desarrollo seguro:

### 1. 🔐 Seguridad de Aplicación (AppSec)
* **Rate Limiting (Anti-DoS):** Protección contra ataques de fuerza bruta y denegación de servicio. Límite de 5 intentos por minuto en login.
* **Gestión de Sesiones:** Uso de `Flask-Login` con protección de cookies segura.
* **Hashing de Contraseñas:** Algoritmo `scrypt` para almacenamiento irreversible de credenciales.
* **Control de Acceso (RBAC):** Prevención de vulnerabilidades IDOR. Los usuarios solo pueden acceder y borrar sus propios datos.

### 2. 👁️ Auditoría y Monitoreo
* **Sistema de Logs Forenses:** Registro inmutable de eventos críticos (Login, Registro, Creación/Eliminación de secretos) en `logs/audit.log`.
* **Alertas de Intrusión:** Detección y registro de intentos de acceso no autorizados.

### 3. 🤖 Pipeline CI/CD Seguro (DevSecOps)
* **Análisis Estático (SAST):** Integración de **Bandit** en GitHub Actions.
* **Automated Security Gate:** El pipeline bloquea automáticamente cualquier commit que contenga vulnerabilidades de seguridad (como modo debug activo o secretos hardcodeados).

---

## 🛠️ Instalación y Despliegue Local

Sigue estos pasos para levantar el entorno seguro en tu máquina:

### Prerrequisitos
* Python 3.10+
* Git

### Pasos
1.  **Clonar el repositorio:**
    ```bash
    git clone [https://github.com/VIKO-sudo/DevSecOps-Boveda.git](https://github.com/VIKO-sudo/DevSecOps-Boveda.git)
    cd DevSecOps-Boveda
    ```

2.  **Crear entorno virtual (Sandbox):**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Instalar dependencias:**
    ```bash
    pip install flask flask-sqlalchemy flask-login flask-wtf flask-limiter email_validator
    ```

4.  **Iniciar el Servidor Seguro:**
    ```bash
    python app.py
    ```

5.  **Acceso:**
    Abrir navegador en `http://127.0.0.1:5000`

---

## 📋 Lista de Tareas (Roadmap)

- [x] Arquitectura Base (MVC)
- [x] Base de Datos SQLite
- [x] Pipeline CI/CD con Bandit
- [x] Sistema de Logs
- [x] Protección contra Fuerza Bruta (Rate Limit)
- [ ] Encriptación de Datos en Reposo (AES-256)
- [ ] Implementación de HTTPS (TLS)

---
**Desarrollado por:** Víctor Fernández (VIKO-sudo)
*Proyecto académico de DevSecOps*