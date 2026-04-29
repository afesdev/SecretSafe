# SecretSafe

Gestor de contrasenas local-first para escritorio, construido con **Tauri + Rust + Dioxus**.  
SecretSafe protege credenciales en una boveda cifrada local (`.vault`), sin depender de servidores en la nube.

## Objetivo del proyecto

SecretSafe busca ofrecer una alternativa privada y autocontenida para gestion de secretos personales y de trabajo:

- Cifrado robusto de boveda local.
- Control total del archivo por parte del usuario.
- Flujo de uso rapido para crear, buscar, editar y auditar credenciales.
- Integracion opcional con extension de navegador mediante bridge local.

## Caracteristicas principales

- Boveda local cifrada con formato propio (`.vault`).
- Desbloqueo por contrasena maestra.
- Soporte de desbloqueo con Windows (Hello/PIN/huella/rostro, segun disponibilidad del sistema).
- CRUD completo de secretos y carpetas.
- Generador de contrasenas seguras.
- Historial de cambios y de contrasenas por entrada.
- Importacion desde formatos externos (incluye CSV/KeePass y deteccion de fuente).
- Exportacion:
  - CSV (texto plano para interoperabilidad).
  - Boveda cifrada con contrasena secundaria.
- Backups versionados y restauracion punto-en-tiempo.
- Bridge local para autocompletado con extension (`127.0.0.1:47635`).

## Arquitectura

La app esta dividida en dos capas:

- **Frontend (`src/`)**
  - Dioxus (UI).
  - Estado de sesion, modales, flujo de desbloqueo y operaciones de usuario.
  - Llamadas a comandos Tauri mediante `src/tauri_api.rs`.

- **Backend (`src-tauri/src/`)**
  - Rust + Tauri commands.
  - Cifrado/descifrado de boveda.
  - Persistencia, backups, import/export.
  - Integracion de desbloqueo con Windows.
  - Bridge HTTP local para extension.

## Estructura del repositorio

```text
.
|- src/                          # Frontend Dioxus
|  |- app.rs                     # UI principal y flujos de usuario
|  |- tauri_api.rs               # Cliente de comandos Tauri
|  |- main.rs
|
|- src-tauri/                    # Backend Tauri/Rust
|  |- src/
|  |  |- lib.rs                  # Registro de comandos y bootstrap
|  |  |- commands.rs             # API de comandos invocables desde UI
|  |  |- vault.rs                # Logica principal de boveda
|  |  |- crypto.rs               # Argon2id + XChaCha20-Poly1305
|  |  |- storage.rs              # Lectura/escritura y backups
|  |  |- import.rs               # Importadores
|  |  |- windows_unlock.rs       # Proteccion local de credencial en Windows
|  |  |- windows_consent.rs      # Verificacion de identidad con Windows Hello
|  |  |- bridge.rs               # Bridge local para extension
|  |  |- dialog.rs               # Dialogos nativos de abrir/guardar
|  |  |- models.rs               # Modelos compartidos
|  |  |- error.rs                # Tipos de error
|  |
|  |- tauri.conf.json            # Configuracion de app/ventana/bundles
|  |- scripts/                   # Scripts de build de instaladores
|
|- browser-extension/            # Extension (MVP) para autofill local
|- assets/                       # Tailwind input y recursos de estilo
|- Cargo.toml                    # Crate frontend + workspace
|- package.json                  # Scripts de desarrollo/build
`- README.md
```

## Seguridad y criptografia

SecretSafe usa cifrado simetrico moderno sobre el payload de la boveda:

- **KDF:** Argon2id
  - `memory_cost_kib: 65536` (64 MiB)
  - `time_cost: 3`
  - `parallelism: 1`
  - `salt` aleatoria por sellado
- **Cipher:** XChaCha20-Poly1305
  - `nonce` aleatorio por sellado

Notas:

- La boveda se abre con la contrasena maestra; una contrasena incorrecta no descifra el contenido.
- Los secretos quedan en el equipo del usuario (modelo local-first).
- El desbloqueo con Windows agrega una segunda via de autenticacion local al dispositivo.

## Desbloqueo con Windows

En Windows, SecretSafe permite habilitar desbloqueo local de boveda:

1. Se activa desde una sesion ya desbloqueada con contrasena maestra.
2. La contrasena maestra se protege localmente con APIs de Windows (DPAPI).
3. Al desbloquear por esta via, se solicita verificacion de identidad con Windows Hello.

Importante:

- El metodo exacto (PIN, huella, rostro o credencial del sistema) depende de la configuracion del equipo.
- Si Windows Hello no esta disponible o configurado, la app lo informa y no desbloquea.

## Requisitos

- **Windows 10/11** (target principal del proyecto actual).
- **Rust** (toolchain estable).
- **Bun** (scripts de frontend y orchestracion).
- WebView2 (requerido por Tauri en Windows, el instalador contempla bootstrapper).

## Desarrollo local

Instalar dependencias JS:

```bash
bun install
```

Modo desarrollo completo (Tauri + frontend):

```bash
bun run dev
```

Desarrollo solo frontend (Tailwind + Dioxus):

```bash
bun run frontend:dev
```

Build frontend:

```bash
bun run build
```

Verificacion Rust:

```bash
cargo check
```

## Build y empaquetado

La configuracion de bundling vive en `src-tauri/tauri.conf.json`.

Actualmente se generan instaladores para Windows:

- NSIS
- MSI (WiX)

Scripts auxiliares:

```bash
bun run installer:assets
bun run installer:release
```

## Formato de boveda y backups

- Archivo principal: `*.vault`.
- Backups automaticos en carpeta `.backups` junto a la boveda.
- Retencion de backups en backend (limpieza automatica de antiguos).

## Bridge para extension (MVP)

Servicio HTTP local:

- `GET /health`
- `POST /pair/verify`
- `POST /vault/search`
- `POST /vault/fill`

Caracteristicas:

- Binding local `127.0.0.1:47635`.
- Emparejamiento por PIN temporal.
- Token de sesion en memoria con expiracion.

Documentacion de extension: `browser-extension/README.md`.

## Flujo recomendado de usuario

1. Crear o abrir boveda.
2. Desbloquear con contrasena maestra.
3. (Opcional) activar desbloqueo con Windows.
4. Gestionar secretos, carpetas y auditoria.
5. Exportar y/o restaurar backups periodicamente.

## Estado del proyecto

Proyecto en evolucion activa.  
Se priorizan:

- robustez de cifrado y persistencia local,
- UX de seguridad (autobloqueo, desbloqueo seguro),
- capacidades de import/export y continuidad operativa.

## Roadmap sugerido

- Mejorar telemetria local de errores (opt-in).
- Fortalecer pruebas end-to-end de import/export y recovery.
- Endurecer canal bridge-extension (firmado/hmac por mensaje).
- Mejorar documentacion para contribuidores.

## Licencia

La configuracion actual de bundle declara licencia **Proprietary**.  
Si vas a publicar este repositorio como open source, define aqui la licencia final (por ejemplo MIT/Apache-2.0) y alinea `tauri.conf.json`.

## Creditos

Desarrollado con:

- [Tauri](https://tauri.app/)
- [Dioxus](https://dioxuslabs.com/)
- [Rust](https://www.rust-lang.org/)
- [Tailwind CSS](https://tailwindcss.com/)
