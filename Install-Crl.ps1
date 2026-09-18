# encoding: UTF-8
#requires -Version 5.1
<#
.SYNOPSIS
  Устанавливает опубликованные списки отзыва (CRL) в хранилище «Промежуточные
  центры сертификации» компьютера (mCA) через certmgr КриптоПро.

.DESCRIPTION
  Парная часть к Publish-Crl.ps1. Выход в интернет не нужен: списки берутся
  из каталога публикации.

  Проверка отзыва находит свежий список локально и не обращается к сети. Если
  списка нет или он просрочен, КриптоПро скачивает его при каждой операции
  подписи, а без доступа в интернет ждёт сетевого таймаута.

  Уже установленный файл повторно не ставится: для каждого списка хранятся его
  размер с отметкой времени и SHA256.

.PARAMETER CrlRoot
  Каталог публикации, в который пишет Publish-Crl.ps1.

.PARAMETER Force
  Установить все списки заново, не сверяясь с сохранённым состоянием.

.NOTES
  itforprof.com by Konstantin Tyutyunnik
  https://github.com/IT-for-Prof/cryptopro-offline-crl

  Значения для конкретной площадки задаются в CryptoCRL.local.psd1 рядом со
  скриптом. Параметр командной строки важнее файла.
#>

[CmdletBinding()]
param(
  [Parameter()][string]$CrlRoot,
  [Parameter()][string]$StateRoot        = 'C:\ProgramData\Scripts\CryptoCRL\state',
  [Parameter()][string]$LogRoot          = 'C:\ProgramData\Scripts\Logs\CryptoCRL',
  [Parameter()][int]   $LogRetentionDays = 14,
  [Parameter()][switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$SettingsFile = Join-Path $PSScriptRoot 'CryptoCRL.local.psd1'
if (Test-Path -LiteralPath $SettingsFile) {
  try {
    $settings = Import-PowerShellDataFile -LiteralPath $SettingsFile
  } catch {
    [Console]::Error.WriteLine(('Не читается {0}: {1}' -f $SettingsFile, $_.Exception.Message))
    exit 2
  }
  # Ключи, которых нет среди параметров этого скрипта, пропускаются: файл общий
  # для Publish-Crl и Install-Crl.
  foreach ($k in $settings.Keys) {
    if ($MyInvocation.MyCommand.Parameters.ContainsKey($k) -and -not $PSBoundParameters.ContainsKey($k)) {
      Set-Variable -Name $k -Value $settings[$k]
    }
  }
}

if (-not (Test-Path -LiteralPath $LogRoot -PathType Container)) {
  New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
}
$LogFile = Join-Path $LogRoot ('install-{0}.log' -f (Get-Date -Format 'ddMMyyyy'))

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('INFO','OK','WARN','ERROR')][string]$Level,
    [Parameter(Mandatory=$true)][string]$Message
  )
  $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'), $Level, $Message
  try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
  Write-Information -MessageData $line
}

function Remove-OldLogs {
  param(
    [Parameter(Mandatory=$true)][string]$LogDir,
    [Parameter(Mandatory=$true)][int]$RetentionDays
  )
  try {
    $cutoff = (Get-Date).AddDays(-1 * $RetentionDays)
    foreach ($f in @(Get-ChildItem -LiteralPath $LogDir -Filter 'install-*.log' -File -ErrorAction SilentlyContinue)) {
      if ($f.LastWriteTime -lt $cutoff) { try { Remove-Item -LiteralPath $f.FullName -Force } catch { } }
    }
  } catch { }
}

function Get-CertMgrPath {
  foreach ($p in @(
      'C:\Program Files (x86)\Crypto Pro\CSP\certmgr.exe',
      'C:\Program Files\Crypto Pro\CSP\certmgr.exe')) {
    if (Test-Path -LiteralPath $p) { return $p }
  }
  return $null
}

function Test-CrlAlreadyInstalled {
  <#
    Сверяет SHA256 файла с сохранённым после прошлой установки. Отсутствующий,
    пустой или нечитаемый файл состояния означает «не установлен»: лишняя
    установка безвредна, пропущенная — нет.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$StateFile,
    [Parameter(Mandatory=$true)][string]$Hash
  )
  if (-not (Test-Path -LiteralPath $StateFile)) { return $false }
  $prev = (Get-Content -LiteralPath $StateFile -Raw -ErrorAction SilentlyContinue)
  if ([string]::IsNullOrWhiteSpace($prev)) { return $false }
  return ($prev.Trim() -eq $Hash)
}

$exitCode = 0
try {
  Write-Log -Level 'INFO' -Message ('Старт | Host={0} | RunAs={1}' -f $env:COMPUTERNAME, ([Security.Principal.WindowsIdentity]::GetCurrent()).Name)
  Remove-OldLogs -LogDir $LogRoot -RetentionDays $LogRetentionDays

  if ([string]::IsNullOrWhiteSpace($CrlRoot)) {
    Write-Log -Level 'ERROR' -Message ('Не задан CrlRoot: ни параметром, ни в {0}' -f $SettingsFile)
    exit 2
  }

  $certmgr = Get-CertMgrPath
  if ($null -eq $certmgr) {
    Write-Log -Level 'ERROR' -Message 'certmgr.exe КриптоПро не найден — ставить нечем.'
    exit 13
  }
  Write-Log -Level 'INFO' -Message ('certmgr: {0}' -f $certmgr)

  if (-not (Test-Path -LiteralPath $CrlRoot -PathType Container)) {
    Write-Log -Level 'ERROR' -Message ('Каталог публикации недоступен: {0}' -f $CrlRoot)
    exit 8
  }
  if (-not (Test-Path -LiteralPath $StateRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
  }

  $files = @(Get-ChildItem -LiteralPath $CrlRoot -Filter '*.crl' -File -ErrorAction SilentlyContinue)
  if (@($files).Count -eq 0) {
    Write-Log -Level 'ERROR' -Message ('В {0} нет ни одного .crl' -f $CrlRoot)
    exit 11
  }
  Write-Log -Level 'INFO' -Message ('Списков к обработке: {0}' -f @($files).Count)

  $installed = 0; $skipped = 0; $failed = 0

  foreach ($f in $files) {
    $stateFile = Join-Path $StateRoot ($f.Name + '.sha256')
    # Локальная копия: certmgr читает файл несколько раз.
    $local = Join-Path $env:TEMP $f.Name
    try {
      # Отсечка по размеру и времени изменения источника до копирования: списки
      # бывают десятки мегабайт, и без неё каждый прогон гонял бы их по сети ради
      # хэша. Новый выпуск списка меняет и размер, и время; ложное «изменилось»
      # стоит одного лишнего копирования.
      $stamp     = '{0}|{1:o}' -f $f.Length, $f.LastWriteTimeUtc
      $stampFile = Join-Path $StateRoot ($f.Name + '.stamp')
      if (-not $Force -and (Test-Path -LiteralPath $stampFile)) {
        $prevStamp = (Get-Content -LiteralPath $stampFile -Raw -ErrorAction SilentlyContinue)
        if (-not [string]::IsNullOrWhiteSpace($prevStamp) -and $prevStamp.Trim() -eq $stamp) {
          $skipped++
          Write-Log -Level 'INFO' -Message ('{0}: источник не менялся, копирование пропущено.' -f $f.Name)
          continue
        }
      }
      # Хэш считается по локальной копии: он описывает ровно те байты, которые
      # уйдут в хранилище, и файл идёт по сети один раз.
      Copy-Item -LiteralPath $f.FullName -Destination $local -Force
      $hash = (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash

      if (-not $Force -and (Test-CrlAlreadyInstalled -StateFile $stateFile -Hash $hash)) {
        # Отметка пишется и здесь, иначе при совпавшем хэше, но новой отметке
        # источника копирование повторялось бы на каждом прогоне.
        Set-Content -LiteralPath $stampFile -Value $stamp -Encoding ASCII
        $skipped++
        Write-Log -Level 'INFO' -Message ('{0}: уже установлен, пропуск.' -f $f.Name)
        continue
      }

      # В PowerShell 5.1 при $ErrorActionPreference = 'Stop' любая строка в stderr
      # нативной программы становится ошибкой NativeCommandError, даже при коде 0.
      # Решение принимается по коду возврата certmgr.
      $out = & {
        $ErrorActionPreference = 'Continue'
        & $certmgr -inst -store mCA -crl -file $local 2>&1
      }
      $rc  = $LASTEXITCODE

      if ($rc -eq 0) {
        Set-Content -LiteralPath $stateFile -Value $hash -Encoding ASCII
        Set-Content -LiteralPath $stampFile -Value $stamp -Encoding ASCII
        $installed++
        Write-Log -Level 'OK' -Message ('{0}: установлен ({1:N0} байт)' -f $f.Name, $f.Length)
      } else {
        $failed++
        $tail = (@($out) | Where-Object { $_ } | Select-Object -Last 2) -join ' | '
        Write-Log -Level 'ERROR' -Message ('{0}: certmgr вернул {1}. {2}' -f $f.Name, $rc, $tail)
      }
    } catch {
      $failed++
      Write-Log -Level 'ERROR' -Message ('{0}: ошибка установки. {1}' -f $f.Name, $_.Exception.Message)
    } finally {
      Remove-Item -LiteralPath $local -Force -ErrorAction SilentlyContinue
    }
  }

  Write-Log -Level $(if ($failed -gt 0) { 'WARN' } else { 'OK' }) -Message ('Готово. Установлено: {0}; пропущено: {1}; ошибок: {2}.' -f $installed, $skipped, $failed)
  if ($failed -gt 0) { $exitCode = 1 }

} catch {
  Write-Log -Level 'ERROR' -Message ('Необработанная ошибка [{0}]: {1}' -f $_.Exception.GetType().Name, $_.Exception.Message)
  try { foreach ($l in ($_.ScriptStackTrace -split "`r?`n")) { Write-Log -Level 'ERROR' -Message ('  стек: {0}' -f $l) } } catch { }
  $exitCode = 10
}

exit $exitCode
