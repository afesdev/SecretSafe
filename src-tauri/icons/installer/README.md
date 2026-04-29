# SecretSafe Installer Branding

Estos bitmaps se usan en los instaladores de Windows:

- `nsis-header.bmp` - `150x57` (header NSIS)
- `nsis-sidebar.bmp` - `164x314` (sidebar NSIS en bienvenida/final)
- `wix-banner.bmp` - `493x58` (banner MSI/WiX)
- `wix-dialog.bmp` - `493x312` (imagen de dialogo MSI/WiX)

## Regenerar assets en 1 comando

Desde `src-tauri`:

`powershell -ExecutionPolicy Bypass -File .\scripts\generate-installer-assets.ps1`

Opcionalmente puedes indicar:

`powershell -ExecutionPolicy Bypass -File .\scripts\generate-installer-assets.ps1 -SourcePng "icons\icon.png" -BrandText "SecretSafe"`

El script sobrescribe los 4 `.bmp` con dimensiones compatibles para NSIS/WiX.

## Flujo para diseno corporativo

1. Reemplaza `icons/icon.png` con tu logo maestro.
2. Ejecuta el script.
3. Compila el instalador.

## Release corporativo en un comando

Desde la raiz del proyecto:

`bun run installer:release`

Este comando:

1. Regenera los assets del wizard.
2. Ejecuta `cargo tauri build --bundles nsis,msi`.
3. Copia artefactos versionados a `dist/installers` con nombres corporativos:
   - `SecretSafe-setup.exe`
   - `SecretSafe-corporate.msi`
