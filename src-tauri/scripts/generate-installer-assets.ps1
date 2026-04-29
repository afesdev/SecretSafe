param(
  [string]$SourcePng  = "icons/icon.png",
  [string]$OutputDir  = "icons/installer",
  [string]$BrandText  = "SecretSafe",
  [string]$Tagline    = "Gestor local de contrasenas"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

# ── Paleta ─────────────────────────────────────────────────────────────────────
$cBg0    = [System.Drawing.Color]::FromArgb(8,   14,  28)   # vault-950
$cBg1    = [System.Drawing.Color]::FromArgb(14,  22,  44)   # vault-900
$cBg2    = [System.Drawing.Color]::FromArgb(18,  28,  56)   # vault-850 (mid)
$cAccent = [System.Drawing.Color]::FromArgb(59,  130, 246)  # brand-500
$cText   = [System.Drawing.Color]::FromArgb(241, 245, 249)  # slate-100
$cMuted  = [System.Drawing.Color]::FromArgb(148, 163, 184)  # slate-400
$cCopy   = [System.Drawing.Color]::FromArgb(71,  85,  105)  # slate-600
$cLight  = [System.Drawing.Color]::FromArgb(248, 250, 252)  # slate-50 (right panel)
$cLightB = [System.Drawing.Color]::FromArgb(241, 245, 249)  # slate-100

# ── Helpers ────────────────────────────────────────────────────────────────────
function New-VGradientBrush([int]$x, [int]$y, [int]$w, [int]$h,
                             [System.Drawing.Color]$c0, [System.Drawing.Color]$c1) {
    return New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        [System.Drawing.Rectangle]::new($x, $y, $w, [Math]::Max($h, 1)),
        $c0, $c1,
        [System.Drawing.Drawing2D.LinearGradientMode]::Vertical
    )
}

function Add-GlowCircle($g, [float]$cx, [float]$cy, [float]$r, [int]$alpha) {
    $col = [System.Drawing.Color]::FromArgb($alpha, $cAccent.R, $cAccent.G, $cAccent.B)
    $b   = New-Object System.Drawing.SolidBrush($col)
    $g.FillEllipse($b, $cx - $r, $cy - $r, $r * 2, $r * 2)
    $b.Dispose()
}

function New-Graphics($bmp) {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    return $g
}

function Save-Bmp($bmp, [string]$path) {
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Bmp)
}

# Dibuja un rounded-rect (recorte manual de esquinas con fondo)
function Draw-RoundRect($g, [System.Drawing.Brush]$brush,
                         [float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($x,           $y,           $r*2, $r*2, 180, 90)
    $path.AddArc($x+$w-$r*2,  $y,           $r*2, $r*2, 270, 90)
    $path.AddArc($x+$w-$r*2,  $y+$h-$r*2,  $r*2, $r*2,   0, 90)
    $path.AddArc($x,           $y+$h-$r*2,  $r*2, $r*2,  90, 90)
    $path.CloseFigure()
    $g.FillPath($brush, $path)
    $path.Dispose()
}

# ── WiX Dialog 493 x 312 ───────────────────────────────────────────────────────
# FONDO COMPLETO del diálogo de bienvenida MSI.
# Panel izquierdo (0–164): artwork oscuro de marca.
# Panel derecho (164–493): claro — aquí Windows superpone sus controles.
function New-WixDialog($src, [string]$out) {
    $W = 493; $H = 312
    $LP = 164          # ancho del panel izquierdo (left panel)

    $bmp = New-Object System.Drawing.Bitmap($W, $H)
    $g   = New-Graphics $bmp
    try {
        # ── Panel derecho — blanco/slate-50 ────────────────────────────────────
        $gbR = New-VGradientBrush $LP 0 ($W - $LP) $H $cLight $cLightB
        $g.FillRectangle($gbR, $LP, 0, ($W - $LP), $H)
        $gbR.Dispose()

        # Borde sutil derecho
        $penEdge = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(200, 220, 235), 1)
        $g.DrawLine($penEdge, ($W - 1), 0, ($W - 1), $H)
        $penEdge.Dispose()

        # ── Panel izquierdo — gradiente oscuro ─────────────────────────────────
        $gbL = New-VGradientBrush 0 0 $LP $H $cBg0 $cBg2
        $g.FillRectangle($gbL, 0, 0, $LP, $H)
        $gbL.Dispose()

        # Glow radial tras el logo
        Add-GlowCircle $g -cx ($LP / 2) -cy 90 -r 90 -alpha 20

        # ── Barra de acento azul (ancho completo) ──────────────────────────────
        $bAcc = New-Object System.Drawing.SolidBrush($cAccent)
        $g.FillRectangle($bAcc, 0, 0, $W, 3)
        $bAcc.Dispose()

        # ── Separador vertical entre paneles ───────────────────────────────────
        $penSep = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(180, 200, 220), 1)
        $g.DrawLine($penSep, $LP, 3, $LP, $H)
        $penSep.Dispose()

        # ── Logo ───────────────────────────────────────────────────────────────
        $lSz = 68
        $lX  = [int](($LP - $lSz) / 2)
        $lY  = 44
        $g.DrawImage($src, $lX, $lY, $lSz, $lSz)

        # ── Brand name ─────────────────────────────────────────────────────────
        $fName = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
        $bText = New-Object System.Drawing.SolidBrush($cText)
        $fmt   = New-Object System.Drawing.StringFormat
        $fmt.Alignment          = [System.Drawing.StringAlignment]::Center
        $fmt.LineAlignment      = [System.Drawing.StringAlignment]::Near
        $fmt.FormatFlags        = [System.Drawing.StringFormatFlags]::NoWrap
        $centerX = [float]($LP / 2)
        $g.DrawString($BrandText, $fName, $bText, $centerX, [float]($lY + $lSz + 10), $fmt)
        $fName.Dispose()

        # ── Tagline ────────────────────────────────────────────────────────────
        $fTag  = New-Object System.Drawing.Font("Segoe UI", 7.5)
        $bMut  = New-Object System.Drawing.SolidBrush($cMuted)
        $rectT = New-Object System.Drawing.RectangleF(8, [float]($lY + $lSz + 34), ($LP - 16), 36)
        $fmtW  = New-Object System.Drawing.StringFormat
        $fmtW.Alignment     = [System.Drawing.StringAlignment]::Center
        $fmtW.LineAlignment = [System.Drawing.StringAlignment]::Near
        $g.DrawString($Tagline, $fTag, $bMut, $rectT, $fmtW)
        $fTag.Dispose(); $bMut.Dispose(); $fmtW.Dispose()

        # ── Línea decorativa ───────────────────────────────────────────────────
        $penL = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(45, 255, 255, 255), 1)
        $lineY = [float]($lY + $lSz + 76)
        $g.DrawLine($penL, 16.0, $lineY, [float]($LP - 16), $lineY)
        $penL.Dispose()

        # ── Puntos decorativos ─────────────────────────────────────────────────
        $bDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(60, 59, 130, 246))
        foreach ($dx in @(-14, 0, 14)) {
            $g.FillEllipse($bDot, [float]($LP / 2 + $dx - 3), ($lineY + 12), 6.0, 6.0)
        }
        $bDot.Dispose()

        # ── Copyright (solo ASCII para evitar corrupcion de encoding) ──────────
        $fCopy = New-Object System.Drawing.Font("Segoe UI", 7)
        $bCopy = New-Object System.Drawing.SolidBrush($cCopy)
        $g.DrawString("AfesDev | Colombia", $fCopy, $bCopy, $centerX, [float]($H - 22), $fmt)
        $fCopy.Dispose(); $bCopy.Dispose()

        $bText.Dispose(); $fmt.Dispose()
        Save-Bmp $bmp $out
        Write-Host "  [OK] wix-dialog.bmp  ($W x $H)  left=$LP right=$($W-$LP)"
    } finally {
        $g.Dispose(); $bmp.Dispose()
    }
}

# ── WiX Banner 493 x 58 ────────────────────────────────────────────────────────
# Cabecera superior en paginas interiores del MSI.
# Fondo oscuro completo — encima no hay controles de texto criticos.
function New-WixBanner($src, [string]$out) {
    $W = 493; $H = 58
    $bmp = New-Object System.Drawing.Bitmap($W, $H)
    $g   = New-Graphics $bmp
    try {
        # Fondo gradiente horizontal oscuro
        $gbH = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            [System.Drawing.Rectangle]::new(0, 0, $W, 1),
            $cBg0, $cBg2,
            [System.Drawing.Drawing2D.LinearGradientMode]::Horizontal
        )
        $g.FillRectangle($gbH, 0, 0, $W, $H)
        $gbH.Dispose()

        # Barra de acento azul arriba
        $bAcc = New-Object System.Drawing.SolidBrush($cAccent)
        $g.FillRectangle($bAcc, 0, 0, $W, 3)
        $bAcc.Dispose()

        # Borde inferior sutil
        $penBot = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 255, 255), 1)
        $g.DrawLine($penBot, 0, ($H - 1), $W, ($H - 1))
        $penBot.Dispose()

        # Logo
        $lSz = 32
        $lY  = [int](($H - $lSz) / 2) + 1
        $g.DrawImage($src, 14, $lY, $lSz, $lSz)

        # Separador vertical
        $penV = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 255, 255), 1)
        $g.DrawLine($penV, 54, 10, 54, ($H - 10))
        $penV.Dispose()

        # Nombre app
        $fName = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
        $bText = New-Object System.Drawing.SolidBrush($cText)
        $g.DrawString($BrandText, $fName, $bText, 63.0, 7.0)
        $fName.Dispose()

        # Tagline
        $fTag = New-Object System.Drawing.Font("Segoe UI", 7.5)
        $bMut = New-Object System.Drawing.SolidBrush($cMuted)
        $g.DrawString($Tagline, $fTag, $bMut, 64.0, 29.0)
        $fTag.Dispose(); $bMut.Dispose(); $bText.Dispose()

        # Circulo decorativo derecho
        $bCirc = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 59, 130, 246))
        $g.FillEllipse($bCirc, [float]($W - 48), [float](($H - 32) / 2), 32.0, 32.0)
        $bCirc.Dispose()

        Save-Bmp $bmp $out
        Write-Host "  [OK] wix-banner.bmp   ($W x $H)"
    } finally {
        $g.Dispose(); $bmp.Dispose()
    }
}

# ── NSIS Sidebar 164 x 314 ─────────────────────────────────────────────────────
# Panel lateral izquierdo del wizard NSIS.
function New-NsisSidebar($src, [string]$out) {
    $W = 164; $H = 314
    $bmp = New-Object System.Drawing.Bitmap($W, $H)
    $g   = New-Graphics $bmp
    try {
        $gb = New-VGradientBrush 0 0 $W $H $cBg0 $cBg2
        $g.FillRectangle($gb, 0, 0, $W, $H)
        $gb.Dispose()

        # Glow central-superior
        Add-GlowCircle $g -cx ($W / 2) -cy 75 -r 100 -alpha 22

        # Barra de acento izquierda (3px)
        $bAcc = New-Object System.Drawing.SolidBrush($cAccent)
        $g.FillRectangle($bAcc, 0, 0, 3, $H)
        $bAcc.Dispose()

        # Logo
        $lSz = 68
        $lX  = [int](($W - $lSz) / 2)
        $g.DrawImage($src, $lX, 38, $lSz, $lSz)

        # Nombre
        $fName = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
        $bText = New-Object System.Drawing.SolidBrush($cText)
        $fmt   = New-Object System.Drawing.StringFormat
        $fmt.Alignment = [System.Drawing.StringAlignment]::Center
        $g.DrawString($BrandText, $fName, $bText, [float]($W / 2), 116.0, $fmt)
        $fName.Dispose()

        # Tagline
        $fTag  = New-Object System.Drawing.Font("Segoe UI", 7.5)
        $bMut  = New-Object System.Drawing.SolidBrush($cMuted)
        $rectT = New-Object System.Drawing.RectangleF(12, 140.0, ($W - 24), 44)
        $fmtW  = New-Object System.Drawing.StringFormat
        $fmtW.Alignment     = [System.Drawing.StringAlignment]::Center
        $fmtW.LineAlignment = [System.Drawing.StringAlignment]::Near
        $g.DrawString($Tagline, $fTag, $bMut, $rectT, $fmtW)
        $fTag.Dispose(); $bMut.Dispose(); $fmtW.Dispose()

        # Separador horizontal
        $penL = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(38, 255, 255, 255), 1)
        $g.DrawLine($penL, 18.0, 196.0, [float]($W - 18), 196.0)
        $penL.Dispose()

        # Tres puntos decorativos
        $bDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(65, 59, 130, 246))
        foreach ($dx in @(-16, 0, 16)) {
            $g.FillEllipse($bDot, [float]($W / 2 + $dx - 3), 208.0, 6.0, 6.0)
        }
        $bDot.Dispose()

        # Copyright — solo ASCII
        $fCopy = New-Object System.Drawing.Font("Segoe UI", 7)
        $bCopy = New-Object System.Drawing.SolidBrush($cCopy)
        $g.DrawString("AfesDev | Colombia", $fCopy, $bCopy, [float]($W / 2), [float]($H - 20), $fmt)
        $fCopy.Dispose(); $bCopy.Dispose()

        $bText.Dispose(); $fmt.Dispose()
        Save-Bmp $bmp $out
        Write-Host "  [OK] nsis-sidebar.bmp ($W x $H)"
    } finally {
        $g.Dispose(); $bmp.Dispose()
    }
}

# ── NSIS Header 150 x 57 ───────────────────────────────────────────────────────
# Cabecera pequeña en paginas interiores del NSIS.
function New-NsisHeader($src, [string]$out) {
    $W = 150; $H = 57
    $bmp = New-Object System.Drawing.Bitmap($W, $H)
    $g   = New-Graphics $bmp
    try {
        $gb = New-VGradientBrush 0 0 $W $H $cBg0 $cBg2
        $g.FillRectangle($gb, 0, 0, $W, $H)
        $gb.Dispose()

        # Barra de acento arriba
        $bAcc = New-Object System.Drawing.SolidBrush($cAccent)
        $g.FillRectangle($bAcc, 0, 0, $W, 3)
        $bAcc.Dispose()

        # Borde inferior
        $penBot = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(35, 255, 255, 255), 1)
        $g.DrawLine($penBot, 0, ($H - 1), $W, ($H - 1))
        $penBot.Dispose()

        # Logo centrado
        $lSz = 32
        $lX  = [int](($W - $lSz) / 2)
        $lY  = [int](($H - $lSz) / 2) + 2
        $g.DrawImage($src, $lX, $lY, $lSz, $lSz)

        Save-Bmp $bmp $out
        Write-Host "  [OK] nsis-header.bmp  ($W x $H)"
    } finally {
        $g.Dispose(); $bmp.Dispose()
    }
}

# ── Entry point ────────────────────────────────────────────────────────────────
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcTauri  = Split-Path -Parent $scriptDir

$srcPngAbs = if ([System.IO.Path]::IsPathRooted($SourcePng)) { $SourcePng } else { Join-Path $srcTauri $SourcePng }
$outDirAbs = if ([System.IO.Path]::IsPathRooted($OutputDir))  { $OutputDir  } else { Join-Path $srcTauri $OutputDir  }

if (-not (Test-Path $srcPngAbs)) { throw "PNG no encontrado: $srcPngAbs" }
if (-not (Test-Path $outDirAbs)) { New-Item -ItemType Directory -Path $outDirAbs -Force | Out-Null }

Write-Host "Generando assets de instalador..."
$src = [System.Drawing.Image]::FromFile($srcPngAbs)
try {
    New-WixDialog   $src (Join-Path $outDirAbs "wix-dialog.bmp")
    New-WixBanner   $src (Join-Path $outDirAbs "wix-banner.bmp")
    New-NsisSidebar $src (Join-Path $outDirAbs "nsis-sidebar.bmp")
    New-NsisHeader  $src (Join-Path $outDirAbs "nsis-header.bmp")
} finally {
    $src.Dispose()
}
Write-Host "Assets listos en: $outDirAbs"
