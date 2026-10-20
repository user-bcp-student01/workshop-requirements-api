# Workshop Requirements API — Python FastAPI

> **Laboratorio intencionalmente vulnerable.** Ejecutar únicamente en local, repositorios privados y ambientes aislados. No publicar en Internet ni desplegar en CERT/PROD.

API FastAPI que administra tareas del workshop y recibe archivos de requerimientos. Usa SQLite y consume el token emitido por el backend Quarkus.

## Ejecución

Requisitos: Python 3.13.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
# Linux/macOS: export AUTH_TOKEN_PUBLIC_KEY_PATH=/path/to/auth-public.pem
# Windows PowerShell: $env:AUTH_TOKEN_PUBLIC_KEY_PATH = 'C:\path\to\auth-public.pem'
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

`AUTH_TOKEN_PUBLIC_KEY_PATH` debe apuntar a la clave publica PEM que corresponde
a la clave privada configurada en el backend Quarkus. La API verifica JWT RS256,
emisor `workshop-auth-backend`, audiencia `workshop-api` y expiracion. No hay
fallback al formato de token legado; sin clave configurada, las rutas protegidas
responden HTTP 503.
Los fallos de `GET /api/backend-health` conservan HTTP 200 y usan un mensaje
genérico en `body`, sin exponer detalles de excepciones remotas.

Swagger: `http://localhost:8000/docs`

## Endpoints

- `GET /api/tasks`
- `POST /api/tasks`
- `GET /api/summary`
- `POST /api/requirements`
- `GET /api/backend-health`

La rama `main` conserva SQL concatenado, manejo inseguro de nombres de archivo, conexión global y lógica monolítica. La autenticación requiere ahora un JWT RS256 emitido por el backend Quarkus y una clave pública configurada localmente.
