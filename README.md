# Módulo Backend REST (Flask + Auth LDAP + Cifrado Fernet)

Este módulo implementa la API REST central del sistema con autenticación integrada contra el servidor OpenLDAP, almacenamiento seguro con cifrado simétrico en reposo (Fernet) y soporte para rotación dinámica de secretos en caliente.

---

## 🏛️ Características Principales

1. **Autenticación LDAP**:
   - Valida credenciales contra `openldap:389` usando `ldap3`.
   - Consulta atributos del usuario (`cn`, `mail`) y membresía de grupos (`cn=developers`).
2. **Cifrado de Base de Datos (Fernet)**:
   - Los registros se encriptan con clave simétrica AES-128-CBC + HMAC-SHA256 antes de guardarse en SQLite.
   - Garantiza que los datos permanezcan protegidos en reposo.
3. **Validación de `API_SECRET` Dinámico**:
   - Lee el secreto activo desde `/shared/api_secret.txt` en cada petición.
   - Rechaza con `401 Unauthorized` cualquier petición con claves viejas o faltantes.

---

## 🔌 Endpoints de la API

| Método | Endpoint | Cabecera / Auth | Descripción |
|---|---|---|---|
| `POST` | `/api/login` | JSON `{username, password}` | Autentica contra LDAP y retorna datos del usuario. |
| `GET` | `/api/health` | Ninguna | Chequeo de salud del servicio. |
| `GET` | `/api/status` | Ninguna | Diagnóstico de conexión LDAP, SQLite y hashes de secretos. |
| `GET` | `/api/data` | `x-api-key` | Retorna los registros desencriptados de la bóveda. |
| `POST` | `/api/data` | `x-api-key`, JSON `{title, secret_value}` | Cifra y guarda un nuevo registro. |
| `GET` | `/api/raw-database`| Ninguna | Muestra los registros crudos cifrados en SQLite. |

---

## 🛠️ Ejecución Local

```bash
pip install -r requirements.txt
python app.py
```
