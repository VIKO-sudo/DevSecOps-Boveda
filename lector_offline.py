import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import getpass
import time
import sys

def generar_llave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=600000, backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def activar_honeypot():
    print("\n[!] ALERTA: Detectada anomalía en la entropía de descifrado.")
    time.sleep(1)
    print("[+] Forzando apertura de bóveda secundaria...")
    time.sleep(1.5)
    print("\n--- BÓVEDA DESENCRIPTADA (MODO DE SEGURIDAD) ---")
    print("--------------------------------------------------")
    print("Plataforma: Facebook  | Credencial: osito_amoroso_99")
    print("Plataforma: Gmail     | Credencial: password12345")
    print("Plataforma: Instagram | Credencial: chiquita_bebe01")
    print("Plataforma: Netflix   | Credencial: 12345678")
    print("Plataforma: PayPal    | Credencial: admin_admin")
    print("--------------------------------------------------")
    print("[!] Fin de los registros.\n")
    input("Presiona ENTER para salir...") # <-- ESTO EVITA QUE LA VENTANA SE CIERRE
    sys.exit(0)

def desencriptar_archivo():
    print("=== DEVSECOPS VAULT: LECTOR DE RESCATE OFFLINE ===")
    archivo = input("Nombre del archivo .enc (ej. boveda.enc): ")
    
    try:
        with open(archivo, 'rb') as f:
            datos_exportados = json.loads(f.read().decode())
    except Exception:
        print("[-] Error: Archivo no encontrado o corrupto.")
        input("\nPresiona ENTER para salir...")
        return

    salt = base64.b64decode(datos_exportados['salt'])
    datos_encriptados = datos_exportados['datos']
    
    for intento in range(1, 4):
        password = getpass.getpass(f"Ingresa la contraseña de cifrado (Intento {intento}/3): ")
        llave = generar_llave(password, salt)
        f_crypto = Fernet(llave)
        
        try:
            datos_planos = f_crypto.decrypt(datos_encriptados.encode()).decode()
            credenciales = json.loads(datos_planos)
            
            print("\n[+] Llave maestra aceptada. Desencriptando bloque AES-256...")
            time.sleep(1)
            print("\n--- BÓVEDA DESENCRIPTADA (OFFLINE) ---")
            print("--------------------------------------------------")
            for c in credenciales:
                print(f"Plataforma: {c['title']} | Credencial: {c['content']}")
            print("--------------------------------------------------")
            print("[!] Fin de los registros.\n")
            input("Presiona ENTER para salir...") # <-- EVITA QUE SE CIERRE AL TENER ÉXITO
            return
            
        except InvalidToken:
            print("[-] Contraseña incorrecta o bloque corrupto.\n")
            time.sleep(0.5)
            
    activar_honeypot()

if __name__ == "__main__":
    desencriptar_archivo()