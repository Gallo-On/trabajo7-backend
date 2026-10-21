# 🛡️ Informe de Auditoría de Seguridad y Vulnerabilidades: Backend API

**Proyecto:** `trabajo7-backend` (Security Vault & LDAP Gateway)  
**Fecha de Análisis:** 21 de Octubre de 2026  
**Versión Evaluada:** Rama `main`  
**Herramientas de Evaluación:** Nuclei Vulnerability Scanner v3.2.0 + SAST Code Review  

---

## 1. Resumen Ejecutivo

Se realizó una evaluación integral de seguridad sobre el repositorio de **Backend API**, analizando tanto los endpoints HTTP expuestos como la lógica interna de autenticación, autorización y manejo criptográfico implementada en [app.py](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/app.py) y [Dockerfile](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/Dockerfile).

Durante el escaneo se identificaron **7 vulnerabilidades** distribuidas según su severidad:
- 🔴 **1 Crítica**
- 🟠 **1 Alta**
- 🟡 **3 Medias**
- 🔵 **2 Bajas**

---

## 2. Matriz de Hallazgos

| ID | Vulnerabilidad | Severidad | CWE / OWASP | Archivo / Endpoint Afectado | Complejidad de Corrección |
|:---|:---|:---:|:---:|:---|:---:|
| **SEC-BE-01** | Inyección LDAP en Endpoint de Autenticación | **Crítica** | CWE-90 / OWASP A03 | `/api/login`, [app.py:200,228](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/app.py#L200) | Media |
| **SEC-BE-02** | Exposición Cruda de Bóveda sin Autenticación | **Alta** | CWE-306 / OWASP A01 | `/api/raw-database`, [app.py:368](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/app.py#L368) | Baja |
| **SEC-BE-03** | Política CORS Permisiva (Wildcard `*`) | **Media** | CWE-942 / OWASP A05 | [app.py:12](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/app.py#L12) | Baja |
| **SEC-BE-04** | Vulnerabilidad a Timing Attacks en Validación de API Key | **Media** | CWE-208 / OWASP A02 | [app.py:287,327](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/app.py#L287) | Baja |
| **SEC-BE-05** | Divulgación de Arquitectura Interna y Hashes en `/api/status` | **Media** | CWE-200 / OWASP A01 | `/api/status`, [app.py:133](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/app.py#L133) | Baja |
| **SEC-BE-06** | Ausencia de Cabeceras de Seguridad HTTP Estándar | **Baja** | CWE-693 / OWASP A05 | Middleware HTTP / [app.py](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/app.py) | Baja |
| **SEC-BE-07** | Ejecución de Contenedor Docker con Privilegios Root | **Baja** | CWE-250 / OWASP A05 | [Dockerfile:1-25](file:///c:/Users/gaela/Desktop/9no/Gestión%20de%20seguridad%20de%20la%20información/12oct/trabajo7-backend/Dockerfile#L1-L25) | Media |

---

## 3. Detalle de Vulnerabilidades y Propuestas de Remediación

### SEC-BE-01: Inyección LDAP en Endpoint de Login
- **Severidad:** 🔴 Crítica
- **Descripción:** El parámetro `username` recibido en la petición JSON se concatena directamente en la cadena del filtro de búsqueda LDAP:
  ```python
  user_dn = f"uid={username},ou=users,{LDAP_BASE_DN}"
  # y en la búsqueda administrativa:
  search_filter = f"(uid={username})"
  ```
  Sin sanitizar los caracteres reservados de LDAP (`*`, `(`, `)`, `\`, `NUL`), un atacante puede alterar la lógica del árbol o consultar atributos no autorizados mediante inyección de filtros LDAP.
- **Impacto:** Posible bypass de lógica de consulta, enumeración de usuarios del directorio y extracción no autorizada de atributos.
- **Remediación propuesta:**
  1. Utilizar la función de escape nativa de `ldap3`: `ldap3.utils.conv.escape_filter_chars(username)`.
  2. Implementar una expresión regular estricta que valide que el nombre de usuario solo contenga caracteres alfanuméricos (`^[a-zA-Z0-9._-]+$`).

---

### SEC-BE-02: Exposición Cruda de Bóveda sin Autenticación
- **Severidad:** 🟠 Alta
- **Descripción:** La ruta `/api/raw-database` no valida la cabecera `x-api-key` ni ninguna sesión. Devuelve todos los registros almacenados, incluyendo títulos, fecha de creación y texto cifrado.
- **Impacto:** Fuga de metadatos sensibles (títulos de credenciales como AWS, Stripe, Base de Datos) y exposición del texto cifrado que permite ataques criptográficos offline.
- **Remediación propuesta:** Exigir validación estricta de la clave `x-api-key` en `/api/raw-database`, idéntico a `/api/data`.

---

### SEC-BE-03: Política CORS Permisiva (Wildcard `*`)
- **Severidad:** 🟡 Media
- **Descripción:** La línea `CORS(app, resources={r"/*": {"origins": "*"}}) ` permite que cualquier sitio web malicioso en el navegador del usuario realice peticiones cruzadas contra la API.
- **Impacto:** Peticiones Cross-Origin no deseadas y potencial abuso de endpoints locales.
- **Remediación propuesta:** Restringir los orígenes autorizados a variables de entorno o dominios específicos:
  ```python
  ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080").split(",")
  CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}})
  ```

---

### SEC-BE-04: Vulnerabilidad a Timing Attacks en Validación de API Key
- **Severidad:** 🟡 Media
- **Descripción:** En las líneas 287 y 327 se compara la clave API con el operador de desigualdad estándar:
  ```python
  if client_api_key != current_api_secret:
  ```
  La comparación estándar de Python termina en el primer carácter diferente, lo que provoca discrepancias medibles en el tiempo de respuesta.
- **Impacto:** Deducción carácter a carácter del secreto compartido mediante análisis estadístico de tiempos de respuesta.
- **Remediación propuesta:** Utilizar comparación en tiempo constante:
  ```python
  import hmac
  if not hmac.compare_digest(str(client_api_key), str(current_api_secret)):
  ```

---

### SEC-BE-05: Divulgación de Arquitectura Interna y Hashes en `/api/status`
- **Severidad:** 🟡 Media
- **Descripción:** El endpoint `/api/status` expone sin autenticación el hostname del servidor LDAP interno (`openldap`), el puerto, el Base DN (`dc=example,dc=com`) y los primeros 12 caracteres del hash SHA-256 de las contraseñas y claves activas.
- **Impacto:** Facilita la fase de reconocimiento (reconnaissance) a atacantes externos para mapear la red interna y verificar si los secretos rotados coinciden con diccionarios conocidos.
- **Remediación propuesta:** Proteger el endpoint con `x-api-key` o reducir la salida pública a un estado general (`{"status": "online"}`).

---

### SEC-BE-06: Ausencia de Cabeceras de Seguridad HTTP Estándar
- **Severidad:** 🔵 Baja
- **Descripción:** La API no inyecta cabeceras de endurecimiento en las respuestas HTTP.
- **Impacto:** Mayor superficie de ataque frente a ataques de MIME sniffing o incrustación en iframes.
- **Remediación propuesta:** Añadir un hook `after_request` en Flask:
  ```python
  @app.after_request
  def set_security_headers(response):
      response.headers["X-Content-Type-Options"] = "nosniff"
      response.headers["X-Frame-Options"] = "DENY"
      response.headers["Content-Security-Policy"] = "default-src 'self'"
      return response
  ```

---

### SEC-BE-07: Ejecución de Contenedor Docker con Privilegios Root
- **Severidad:** 🔵 Baja
- **Descripción:** El contenedor de Python corre bajo el usuario `root` (UID 0) sin definir una directiva `USER appuser`.
- **Impacto:** Si un atacante logra ejecución remota de código (RCE), hereda privilegios de superusuario dentro del contenedor.
- **Remediación propuesta:** Crear un usuario de sistema sin privilegios en el `Dockerfile` y cambiar la ejecución a dicho usuario antes del `CMD`.
