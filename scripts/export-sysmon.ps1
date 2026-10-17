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
# Las ejecuciones de este script (la de ahora y las anteriores) no son
# actividad del equipo. Se reconocen por su línea de comandos, que se lee pero
# no se exporta, y se sigue a ese proceso por su ProcessGuid, que, a
# diferencia del PID, Windows no reutiliza.
$ownProcesses = @{}
$count = 0
$own = 0
$failure = $null
try {
    # Del más antiguo al más reciente: la creación de un proceso llega antes
    # que lo que ese proceso hace.
    Get-WinEvent -FilterHashtable $filter -Oldest | ForEach-Object {
        $values = @{}
        foreach ($data in ([xml]$_.ToXml()).Event.EventData.Data) {
            if ($data.'#text') { $values[$data.Name] = $data.'#text' }
        }
        $guid = $values['ProcessGuid']
        if ($guid -and $_.Id -eq 1 -and $values['CommandLine'] -like '*export-sysmon.ps1*') {
            $ownProcesses[$guid] = $true
        }
        if ($guid -and $ownProcesses.ContainsKey($guid)) { $own++; return }

        $record = [ordered]@{
            '@timestamp'      = $_.TimeCreated.ToUniversalTime().ToString('o')
            'host.name'       = $_.MachineName
            'sysmon.event_id' = $_.Id
        }
        foreach ($name in $wanted) {
            if ($values.ContainsKey($name)) { $record[$name] = $values[$name] }
        }
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

Write-Host "$count eventos de Sysmon de los últimos $Days días -> $path"
Write-Host "($own eventos de ejecuciones de este script, omitidos)"
Write-Host 'Siguiente paso:'
Write-Host "  .\target\release\ttpblast.exe search --query queries\phishing-lateral.txt --events $Out"
