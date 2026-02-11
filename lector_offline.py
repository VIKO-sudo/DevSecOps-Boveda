import json
import base64
import hashlib
import getpass
from cryptography.fernet import Fernet, InvalidToken

print("==================================================")
print(" 🛡️ DESENCRIPTADOR DE RESPALDO (OFFLINE MODE) 🛡️")
print("==================================================")

archivo = input("📁 Nombre del archivo a leer (ej. boveda_viko.enc): ")
password = getpass.getpass("🔑 Ingresa la Contraseña de Cifrado (no se verá al escribir): ")

# Mismo algoritmo de derivación que el servidor
digest = hashlib.sha256(password.encode()).digest()
key = base64.urlsafe_b64encode(digest)

try:
    # Intentar abrir y leer
    with open(archivo, 'rb') as f:
        datos_encriptados = f.read()
    
    # Desencriptar
    cipher_suite = Fernet(key)
    datos_crudos = cipher_suite.decrypt(datos_encriptados)
    
    # Formatear el JSON para que se vea bonito
    secretos = json.loads(datos_crudos.decode('utf-8'))
    
    print("\n✅ ACCESO CONCEDIDO. Desencriptación exitosa.\n")
    for sec in secretos:
        print(f"📌 Plataforma: {sec['Plataforma']}")
        print(f"   Credencial: {sec['Credencial']}\n")
        
except FileNotFoundError:
    print("\n❌ Error: No se encontró el archivo. Asegúrate de que esté en la misma carpeta.")
except InvalidToken:
    print("\n🚨 ACCESO DENEGADO: Contraseña incorrecta o archivo corrupto.")
except Exception as e:
    print(f"\n❌ Error fatal: {e}")




    