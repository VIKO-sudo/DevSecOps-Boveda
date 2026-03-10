# DevSecOps Vault - Arquitectura Zero-Knowledge

Plataforma de gestión de secretos y credenciales desarrollada bajo la metodología **DevSecOps**, integrando seguridad ofensiva y defensiva desde el diseño (Security by Design).

![Estado de Seguridad](https://github.com/VIKO-sudo/DevSecOps-Boveda/actions/workflows/security.yml/badge.svg)

##Arquitectura de Seguridad Implementada

Este proyecto supera las validaciones estándar e implementa defensas contra vectores de ataque del mundo real:

### 1. Criptografía y Protección de Datos (Data at Rest)
* **Zero-Knowledge Database:** Implementación de **AES-256 (Fernet)**. La base de datos local (`SQLite`) almacena los secretos cifrados de forma transparente (TDE). Si la BD es exfiltrada, los datos son matemáticamente ilegibles.
* **Derivación de Claves (Key Stretching):** El sistema de exportación de respaldos utiliza **PBKDF2 con 600,000 iteraciones** y `Salt` aleatoria para mitigar ataques de fuerza bruta offline mediante GPU.

### 2.Gestión de Identidad y Acceso (IAM)
* **Autenticación Multi-Factor (MFA):** Implementación de **TOTP (Time-Based One-Time Password)** RFC 6238. Soporte nativo para Google Authenticator y Authy.
* **Bloqueo de Cuenta (Account Lockout):** Defensa activa contra fuerza bruta online. Congelamiento automático de cuentas tras 5 intentos fallidos.
* **Políticas de Contraseña:** Validación estricta mediante Expresiones Regulares (Regex) exigiendo complejidad alfanumérica y mayúsculas.

### 3.Auditoría y Pipeline DevSecOps
* **Trazabilidad Forense:** Registro inmutable de eventos críticos (Login, 2FA, Exportaciones) en archivos de log.
* **Rate Limiting:** Mitigación de ataques de Denegación de Servicio (DoS) limitando peticiones por IP.
* **Análisis Estático (SAST):** Pipeline CI/CD integrado con **GitHub Actions y Bandit** para bloquear despliegues con vulnerabilidades en el código fuente.

---

## Guía de Despliegue (Instalación Rápida)

Para levantar el entorno seguro en una máquina limpia, ejecutar los siguientes comandos:

```bash
# 1. Clonar el repositorio
git clone [https://github.com/VIKO-sudo/DevSecOps-Boveda.git](https://github.com/VIKO-sudo/DevSecOps-Boveda.git)
cd DevSecOps-Boveda

# 2. Crear y activar el entorno virtual aislado (Sandbox)
python -m venv venv
# En Windows:
.\venv\Scripts\activate
# En Linux/Mac:
# source venv/bin/activate

# 3. Instalar dependencias exactas
pip install -r requirements.txt

# 4. Configurar la Llave Maestra (CRÍTICO)
# Crear un archivo llamado .env en la raíz y agregar una clave Fernet válida:
# FERNET_KEY=TuClaveGeneradaAqui=

# 5. Iniciar el Servidor Seguro
python app.py

Acceso local: http://127.0.0.1:5000

