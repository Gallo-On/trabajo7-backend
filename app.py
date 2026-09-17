import os
import sqlite3
import hashlib
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from ldap3 import Server, Connection, ALL, SUBTREE

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ============================================================================
# Configuración y Variables de Entorno
# ============================================================================
PORT = int(os.getenv("PORT", 5000))
SHARED_SECRET_FILE = os.getenv("SHARED_SECRET_FILE", "/shared/api_secret.txt")
SHARED_LDAP_SECRET_FILE = os.getenv("SHARED_LDAP_SECRET_FILE", "/shared/ldap_secret.txt")
DEFAULT_API_SECRET = os.getenv("API_SECRET", "INITIAL-SECRET-2026-KEY")
DEFAULT_LDAP_ADMIN_PASSWORD = os.getenv("LDAP_ADMIN_PASSWORD", "adminpassword")

LDAP_HOST = os.getenv("LDAP_HOST", "openldap")
LDAP_PORT = int(os.getenv("LDAP_PORT", "389"))
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")
LDAP_ADMIN_DN = os.getenv("LDAP_ADMIN_DN", f"cn=admin,{LDAP_BASE_DN}")

DATABASE_PATH = os.getenv("DATABASE_PATH", "/app/data/secrets_vault.db")
DATABASE_ENCRYPTION_KEY = os.getenv(
    "DATABASE_ENCRYPTION_KEY",
    "J8N64wteLy4bsHEPPD6GfjLn6fNfcmga6fnubage_eo="
)

# Inicializar Fernet para cifrado simétrico en reposo
fernet_cipher = Fernet(DATABASE_ENCRYPTION_KEY.encode() if isinstance(DATABASE_ENCRYPTION_KEY, str) else DATABASE_ENCRYPTION_KEY)


def get_current_api_secret() -> str:
    """Lee el secreto dinámico actual desde el archivo compartido o variable de entorno."""
    if os.path.exists(SHARED_SECRET_FILE):
        try:
            with open(SHARED_SECRET_FILE, "r", encoding="utf-8") as f:
                secret = f.read().strip()
                if secret:
                    return secret
        except Exception as e:
            print(f"[BACKEND] Error leyendo {SHARED_SECRET_FILE}: {e}")
    return DEFAULT_API_SECRET


def get_current_ldap_admin_password() -> str:
    """Lee la contraseña administrativa de LDAP actual desde el archivo compartido."""
    if os.path.exists(SHARED_LDAP_SECRET_FILE):
        try:
            with open(SHARED_LDAP_SECRET_FILE, "r", encoding="utf-8") as f:
                secret = f.read().strip()
                if secret:
                    return secret
        except Exception as e:
            print(f"[BACKEND] Error leyendo {SHARED_LDAP_SECRET_FILE}: {e}")
    return DEFAULT_LDAP_ADMIN_PASSWORD


def get_db_connection():
    os.makedirs(os.path.dirname(os.path.abspath(DATABASE_PATH)), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS secrets_vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()

    # Sembrar registros iniciales si está vacía
    cursor.execute("SELECT COUNT(*) FROM secrets_vault")
    count = cursor.fetchone()[0]
    if count == 0:
        sample_secrets = [
            ("Credenciales AWS de demostración", "AWS_ACCESS_KEY=DEMO_ACCESS_KEY; AWS_SECRET=DEMO_SECRET_VALUE"),
            ("Token API de pagos de demostración", "DEMO_STRIPE_TOKEN_NOT_A_REAL_SECRET"),
            ("Cadena de conexión de demostración", "postgresql://demo_user:demo_password@db.example.test:5432/demo_db"),
            ("Certificado SSL de demostración", "-----BEGIN DEMO CERTIFICATE-----\nDEMO_CERTIFICATE_CONTENT\n-----END DEMO CERTIFICATE-----")
        ]
        for title, plain in sample_secrets:
            encrypted = fernet_cipher.encrypt(plain.encode()).decode()
            now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            cursor.execute(
                "INSERT INTO secrets_vault (title, encrypted_payload, created_at) VALUES (?, ?, ?)",
                (title, encrypted, now)
            )
        conn.commit()
    conn.close()


init_db()


# ============================================================================
# Rutas y Endpoints
# ============================================================================

@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "security-backend-api",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }), 200


@app.route("/api/status", methods=["GET"])
def system_status():
    """Retorna el estado de todos los componentes y hashes truncados de los secretos."""
    api_sec = get_current_api_secret()
    ldap_sec = get_current_ldap_admin_password()

    # Comprobar conexión con OpenLDAP
    ldap_ok = False
    ldap_detail = "No conectado"
    try:
        server = Server(LDAP_HOST, port=LDAP_PORT, get_info=ALL, connect_timeout=3)
        conn = Connection(server, user=LDAP_ADMIN_DN, password=ldap_sec, auto_bind=False)
        if conn.bind():
            ldap_ok = True
            ldap_detail = "Conectado y autenticado correctamente"
            conn.unbind()
        else:
            ldap_detail = "Fallo de bind administrativo con credencial actual"
    except Exception as e:
        ldap_detail = str(e)

    # Conteo en BD
    db_count = 0
    try:
        c = get_db_connection()
        db_count = c.cursor().execute("SELECT COUNT(*) FROM secrets_vault").fetchone()[0]
        c.close()
    except Exception:
        pass

    return jsonify({
        "service": "Backend Security Vault & LDAP Gateway",
        "status": "online",
        "ldap_service": {
            "host": LDAP_HOST,
            "port": LDAP_PORT,
            "base_dn": LDAP_BASE_DN,
            "connected": ldap_ok,
            "detail": ldap_detail,
            "admin_secret_hash": hashlib.sha256(ldap_sec.encode()).hexdigest()[:12]
        },
        "backend_secret": {
            "active_secret_hash": hashlib.sha256(api_sec.encode()).hexdigest()[:12],
            "shared_file_present": os.path.exists(SHARED_SECRET_FILE)
        },
        "database": {
            "status": "encrypted_fernet",
            "records_count": db_count
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    }), 200


@app.route("/login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
def ldap_login():
    """Autentica a un usuario contra el directorio OpenLDAP."""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "authenticated": False,
            "detail": "Username and password are required"
        }), 400

    server = Server(LDAP_HOST, port=LDAP_PORT, get_info=ALL, connect_timeout=3)
    user_dn = f"uid={username},ou=users,{LDAP_BASE_DN}"

    try:
        connection = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=False
        )

        if connection.bind():
            user_info = {
                "authenticated": True,
                "username": username,
                "dn": user_dn,
                "cn": username.capitalize(),
                "mail": f"{username}@example.com",
                "groups": ["users"]
            }

            # Consultar atributos y grupos con conexión administrativa
            try:
                admin_pass = get_current_ldap_admin_password()
                admin_conn = Connection(server, user=LDAP_ADMIN_DN, password=admin_pass, auto_bind=True)
                
                # Buscar atributos del usuario
                admin_conn.search(
                    search_base=f"ou=users,{LDAP_BASE_DN}",
                    search_filter=f"(uid={username})",
                    search_scope=SUBTREE,
                    attributes=["cn", "mail", "displayName", "givenName", "sn"]
                )
                if admin_conn.entries:
                    entry = admin_conn.entries[0]
                    if hasattr(entry, "cn") and entry.cn:
                        user_info["cn"] = str(entry.cn.value if hasattr(entry.cn, "value") else entry.cn)
                    if hasattr(entry, "mail") and entry.mail:
                        user_info["mail"] = str(entry.mail.value if hasattr(entry.mail, "value") else entry.mail)

                # Buscar grupos a los que pertenece el usuario
                admin_conn.search(
                    search_base=f"ou=groups,{LDAP_BASE_DN}",
                    search_filter=f"(member={user_dn})",
                    search_scope=SUBTREE,
                    attributes=["cn"]
                )
                user_groups = []
                for g in admin_conn.entries:
                    if hasattr(g, "cn"):
                        val = str(g.cn.value if hasattr(g.cn, "value") else g.cn)
                        user_groups.append(val)
                
                if user_groups:
                    user_info["groups"] = user_groups
                admin_conn.unbind()
            except Exception as search_err:
                print(f"[BACKEND] Error buscando atributos LDAP: {search_err}")

            connection.unbind()
            return jsonify(user_info), 200

        return jsonify({
            "authenticated": False,
            "detail": "Credenciales LDAP inválidas (Usuario o contraseña incorrectos)"
        }), 401

    except Exception as e:
        print(f"[BACKEND] Error en autenticación LDAP: {e}")
        return jsonify({
            "authenticated": False,
            "detail": f"Error comunicando con servidor LDAP: {str(e)}"
        }), 500


@app.route("/api/data", methods=["GET"])
def get_vault_data():
    """Retorna los datos desencriptados de la base de datos previa validación de x-api-key."""
    client_api_key = request.headers.get("x-api-key")
    current_api_secret = get_current_api_secret()

    if not client_api_key:
        return jsonify({
            "error": "Unauthorized",
            "detail": "Falta la cabecera obligatoria 'x-api-key'."
        }), 401

    if client_api_key != current_api_secret:
        return jsonify({
            "error": "Unauthorized",
            "detail": "La clave 'x-api-key' es inválida o ha expirado debido a la rotación de secretos."
        }), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, encrypted_payload, created_at FROM secrets_vault ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    decrypted_items = []
    for row in rows:
        try:
            plain_text = fernet_cipher.decrypt(row["encrypted_payload"].encode()).decode()
        except Exception:
            plain_text = "[ERROR_DECRYPTION_FAILED]"

        decrypted_items.append({
            "id": row["id"],
            "title": row["title"],
            "decrypted_value": plain_text,
            "created_at": row["created_at"]
        })

    return jsonify({
        "status": "success",
        "active_secret_hash": hashlib.sha256(current_api_secret.encode()).hexdigest()[:12],
        "total_records": len(decrypted_items),
        "data": decrypted_items
    }), 200


@app.route("/api/data", methods=["POST"])
def add_vault_data():
    """Cifra y guarda un nuevo secreto en la base de datos SQLite."""
    client_api_key = request.headers.get("x-api-key")
    current_api_secret = get_current_api_secret()

    if not client_api_key or client_api_key != current_api_secret:
        return jsonify({
            "error": "Unauthorized",
            "detail": "Clave 'x-api-key' inválida o no proporcionada."
        }), 401

    payload = request.get_json() or {}
    title = payload.get("title", "").strip()
    secret_value = payload.get("secret_value", "").strip()

    if not title or not secret_value:
        return jsonify({
            "error": "Bad Request",
            "detail": "Se requieren los campos 'title' y 'secret_value'."
        }), 400

    encrypted_blob = fernet_cipher.encrypt(secret_value.encode()).decode()
    created_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO secrets_vault (title, encrypted_payload, created_at) VALUES (?, ?, ?)",
        (title, encrypted_blob, created_at)
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Registro cifrado y almacenado exitosamente.",
        "record": {
            "id": new_id,
            "title": title,
            "ciphertext_sample": encrypted_blob[:30] + "...",
            "created_at": created_at
        }
    }), 201


@app.route("/api/raw-database", methods=["GET"])
def get_raw_database():
    """Muestra el estado crudo (cifrado) de la base de datos sin descifrar."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, encrypted_payload, created_at FROM secrets_vault ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    raw_records = []
    for row in rows:
        raw_records.append({
            "id": row["id"],
            "title": row["title"],
            "raw_encrypted_ciphertext": row["encrypted_payload"],
            "created_at": row["created_at"]
        })

    return jsonify({
        "storage_engine": "SQLite 3",
        "encryption_algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
        "security_guarantee": "Ciphertext stored at rest. Data is completely unreadable without the Fernet Key.",
        "records": raw_records
    }), 200


if __name__ == "__main__":
    print(f"[*] Iniciando Security Backend API en puerto {PORT}...")
    app.run(host="0.0.0.0", port=PORT, debug=False)
