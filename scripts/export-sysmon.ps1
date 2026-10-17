<#
.SYNOPSIS
    Exporta eventos de Sysmon a NDJSON para ttpblast.

.DESCRIPTION
    Lee el registro Microsoft-Windows-Sysmon/Operational y escribe un evento
    JSON por línea, solo con los campos que usa ttpblast: rutas de procesos,
    ficheros y claves de registro, y destinos de red. No exporta líneas de
    comandos, usuarios ni hashes. El fichero se queda en tu equipo (la
    carpeta data\ está excluida de git).

    Ejecútalo en una PowerShell abierta como administrador: el registro de
    Sysmon solo lo pueden leer los administradores.

.PARAMETER Days
    Días hacia atrás que se exportan (7 por defecto).

.PARAMETER Out
    Fichero de salida (data\sysmon\events.ndjson por defecto).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\export-sysmon.ps1 -Days 7
#>
param(
    [int]$Days = 7,
    [string]$Out = 'data\sysmon\events.ndjson'
)

$ErrorActionPreference = 'Stop'

# Eventos que traduce ttpblast: 1 proceso creado, 3 conexión de red,
# 10 acceso a otro proceso, 11 fichero creado, 12-14 registro.
$ids = 1, 3, 10, 11, 12, 13, 14
$wanted = 'Image', 'ParentImage', 'SourceImage', 'TargetImage', 'TargetFilename', 'TargetObject',
          'DestinationIp', 'DestinationHostname', 'DestinationPort', 'Initiated'

# Ruta absoluta respecto a la carpeta actual de PowerShell (.NET usaría otra).
$path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
$dir = Split-Path -Parent $path
if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

$filter = @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = $ids
    StartTime = (Get-Date).AddDays(-$Days)
}

# UTF-8 sin BOM: un BOM al principio estropearía la primera línea JSON.
$writer = New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false)))
# Windows reutiliza los PID: solo son "propios" los eventos con nuestro PID
# desde que arrancó este proceso.
$started = (Get-Process -Id $PID).StartTime.AddSeconds(-5)
$count = 0
$own = 0
$failure = $null
try {
    Get-WinEvent -FilterHashtable $filter | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $record = [ordered]@{
            '@timestamp'      = $_.TimeCreated.ToUniversalTime().ToString('o')
            'host.name'       = $_.MachineName
            'sysmon.event_id' = $_.Id
        }
        $isOwn = $false
        foreach ($data in $xml.Event.EventData.Data) {
            # Este mismo script (su PowerShell y el fichero temporal que crea
            # al arrancar) no es actividad del equipo: se omite.
            if ($data.Name -eq 'ProcessId' -and $data.'#text' -eq "$PID" -and $_.TimeCreated -ge $started) {
                $isOwn = $true
            }
            if ($wanted -contains $data.Name -and $data.'#text') {
                $record[$data.Name] = $data.'#text'
            }
        }
        if ($isOwn) { $own++; return }
        $writer.WriteLine((ConvertTo-Json -InputObject $record -Compress))
        $count++
    }
}
catch {
    $failure = $_.Exception.Message
}
finally {
    $writer.Close()
}

if ($failure) {
    if ($count -eq 0) { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
    Write-Host "No se pudieron leer los eventos de Sysmon: $failure" -ForegroundColor Red
    Write-Host 'Comprueba que Sysmon está instalado (Get-Service Sysmon64), que esta PowerShell'
    Write-Host 'está abierta como administrador y que hay actividad en los últimos días.'
    exit 1
}

Write-Host "$count eventos de Sysmon de los últimos $Days días -> $path ($own del propio script, omitidos)"
Write-Host 'Siguiente paso:'
Write-Host "  .\target\release\ttpblast.exe search --query queries\phishing-lateral.txt --events $Out"
