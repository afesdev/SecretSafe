# SecretSafe Autofill MVP

Extension de navegador MVP para autocompletado local con SecretSafe.

## Estado

- Bridge local en `http://127.0.0.1:47635`
- Endpoints disponibles:
  - `GET /health`
  - `POST /vault/search`
  - `POST /vault/fill`

## Cargar extension en Chrome/Edge

1. Abrir `chrome://extensions` o `edge://extensions`.
2. Activar `Developer mode`.
3. `Load unpacked`.
4. Seleccionar la carpeta `browser-extension`.

## Probar flujo

1. Abrir SecretSafe.
2. Abrir el popup de la extension.
3. En SecretSafe desbloqueado, en sidebar: `Conectar extension` -> `Generar PIN temporal` -> `Copiar PIN`.
4. En el popup de extension pega el PIN y pulsa `Conectar con PIN`.
5. En la web de login, pulsa `Buscar para este sitio`.
6. Selecciona un secreto y pulsa `Autocompletar`.

## Seguridad (MVP)

Este MVP usa PIN temporal generado desde la app y token de sesion en memoria.

- Confirmacion explicita por sitio sensible.
- Hash/HMAC de mensajes entre extension y bridge.
- Reemplazar credenciales crudas por sesion temporal desbloqueada.
