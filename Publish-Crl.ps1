# encoding: UTF-8
#requires -Version 5.1
<#
.SYNOPSIS
  Скачивает списки отзыва (CRL) для сертификатов из контейнеров КриптоПро и
  публикует их в общий каталог, откуда их забирает Install-Crl.ps1.

.DESCRIPTION
  Адреса списков не задаются вручную: они берутся из расширения CRL Distribution
  Points сертификатов в каталоге контейнеров. Сертификат читается из файла .cer
  в каталоге контейнера, а если его нет — из самого контейнера через csptest.

  Точки распространения собираются по всей цепочке каждого сертификата. Отзыв
  проверяется у каждого звена, и без списка головного УЦ цепочка на машине без
  выхода в интернет не строится (0x80092013), даже когда список самого УЦ есть.

  Адреса с одинаковым именем файла считаются зеркалами одного списка и
  перебираются по очереди до первого успешного скачивания.

  Опубликованный файл заменяется только скачанным и опознанным как DER. Если все
  зеркала недоступны, прежняя копия остаётся: без локального списка проверка
  отзыва уходит в сеть и ждёт таймаута.

.PARAMETER KeysRoot
  Каталог с контейнерами КриптоПро.

.PARAMETER CrlRoot
  Каталог публикации, обычно общая папка.

.NOTES
  itforprof.com by Konstantin Tyutyunnik
  https://github.com/IT-for-Prof/cryptopro-offline-crl

  Значения для конкретной площадки задаются в CryptoCRL.local.psd1 рядом со
  скриптом. Параметр командной строки важнее файла.
#>

[CmdletBinding()]
param(
  [Parameter()][string]$KeysRoot,
  [Parameter()][string]$CrlRoot,
  [Parameter()][string]$LogRoot          = 'C:\ProgramData\Scripts\Logs\CryptoCRL',
  [Parameter()][int]   $LogRetentionDays = 14,
  [Parameter()][int]   $TimeoutSec       = 60
)

Set-StrictMode -Version 2.0

# Версия скрипта. Скрипты расходятся копированием по хостам, поэтому версия видна в журнале:
# иначе на вопрос «какая версия на этом хосте» отвечать нечем.
$script:ScriptVersion = '1.1.0'
# Коды возврата csptest, означающие «извлекать нечего»: в контейнере нет сертификата либо нет такого ключа.
$script:ScardNoSuchCertificate = -2146435028
$script:NteKeysetNotDef = -2146893799
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

# -------------------- Настройки площадки --------------------

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

# -------------------- Лог --------------------

if (-not (Test-Path -LiteralPath $LogRoot -PathType Container)) {
  New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
}
$LogFile = Join-Path $LogRoot ('publish-{0}.log' -f (Get-Date -Format 'ddMMyyyy'))

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
    foreach ($f in @(Get-ChildItem -LiteralPath $LogDir -Filter 'publish-*.log' -File -ErrorAction SilentlyContinue)) {
      if ($f.LastWriteTime -lt $cutoff) { try { Remove-Item -LiteralPath $f.FullName -Force } catch { } }
    }
  } catch { }
}

# -------------------- Сбор точек распространения --------------------

function Test-ServicePath {
  <#
    Каталоги, которые не являются контейнерами: BACKUP и KEYS-ARCHIVE (снимки и
    выведенные из работы контейнеры) и служебные каталоги тома. Их сертификаты в
    разбор не берутся; из корзины в публикацию вернулись бы удалённые контейнеры.

    Шаблон привязан к корню: каталог BACKUP внутри контейнера служебным не
    считается. Принимает путь и к файлу, и к самому каталогу.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][string]$Path
  )
  $rx = '^' + [regex]::Escape($Root.TrimEnd('\') + '\') +
        '(BACKUP|KEYS-ARCHIVE|System Volume Information|\$RECYCLE\.BIN)(\\|$)'
  return ($Path -match $rx)
}

function Get-CdpUrl {
  <#
    Адреса из расширения CRL Distribution Points одного сертификата, разобранные
    из текстового представления Format($true). Берутся только http-адреса:
    загрузка по ldap не поддерживается.
  #>
  param([Parameter(Mandatory=$true)]$Certificate)
  $ext = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.31' })
  if (@($ext).Count -eq 0) { return @() }
  return @([regex]::Matches($ext[0].Format($true), 'http[^\s\r\n]+') |
           ForEach-Object { $_.Value.TrimEnd(')', '"', ',', ';') })
}

function Get-ChainCdpUrl {
  <#
    Адреса по всей цепочке сертификата. У листа точка распространения ведёт на
    список УЦ, у сертификата УЦ — на список головного УЦ. Самоподписанный корень
    CDP не несёт.

    Отзыв при построении не проверяется: нужны только адреса. Если цепочка не
    достроена (сертификата УЦ нет в хранилищах), возвращаются адреса найденных
    звеньев и в лог пишется предупреждение.
  #>
  param([Parameter(Mandatory=$true)]$Certificate)
  $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
  $chain.ChainPolicy.RevocationMode = 'NoCheck'
  try {
    # Результат Build не важен: у истёкшего или недоверенного сертификата он $false,
    # но звенья заполнены.
    [void]$chain.Build($Certificate)
    if (@($chain.ChainElements).Count -le 1) {
      Write-Log -Level 'WARN' -Message ('Цепочка не достроена ({0}) — точка распространения УЦ не найдена, звено УЦ останется непроверяемым.' -f $Certificate.Thumbprint)
    }
    $urls = @()
    foreach ($e in $chain.ChainElements) { $urls += @(Get-CdpUrl -Certificate $e.Certificate) }
    return $urls
  } finally {
    $chain.Reset()
  }
}

function Group-CrlUrlByFile {
  <#
    Сводит адреса с одинаковым именем файла в одну запись с несколькими зеркалами.
    Зеркала идут в порядке появления при разборе, в этом же порядке их перебирает
    загрузчик. Записи отсортированы по имени файла.
  #>
  param([Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$Urls)

  $byFile = @{}
  foreach ($url in $Urls) {
    $leaf = ($url -split '/')[-1]
    if ([string]::IsNullOrWhiteSpace($leaf)) { continue }
    if (-not $byFile.ContainsKey($leaf)) { $byFile[$leaf] = New-Object System.Collections.ArrayList }
    if (-not $byFile[$leaf].Contains($url)) { [void]$byFile[$leaf].Add($url) }
  }

  foreach ($k in ($byFile.Keys | Sort-Object)) {
    [pscustomobject]@{ File = $k; Urls = @($byFile[$k]) }
  }
}

function Get-CspTestPath {
  foreach ($p in @('C:\Program Files (x86)\Crypto Pro\CSP\csptest.exe',
                   'C:\Program Files\Crypto Pro\CSP\csptest.exe')) {
    if (Test-Path -LiteralPath $p) { return $p }
  }
  return $null
}

function Get-ContainerName {
  <#
    Дружественное имя контейнера из name.key. КриптоПро находит контейнер только
    по нему: имя каталога и уникальное имя дают 0x80090016.

    name.key — DER: SEQUENCE, внутри строка с тегом 0x16 (IA5String), в которой
    лежит восьмибитный текст в cp1251. Имя берётся ровно по объявленной длине:
    за структурой бывает посторонний хвост.

    Имя уходит в командную строку csptest, запущенного под SYSTEM, а name.key
    может записать пользователь. Имя с обратным слэшем или управляющим символом
    отвергается целиком: экранирование кавычки не спасает, потому что \" в имени
    превращается в \\", CommandLineToArgvW закрывает аргумент, и остаток имени
    становится новыми ключами csptest (например, -expcert). Кавычки, пробелы и
    кириллица допустимы.
  #>
  param([Parameter(Mandatory=$true)][string]$Dir)
  $nk = Join-Path $Dir 'name.key'
  if (-not (Test-Path -LiteralPath $nk)) { return $null }
  $b = [IO.File]::ReadAllBytes($nk)
  # 30 <длина> 16 <длина> <имя>; поддерживается только короткая форма длины (< 128 байт)
  if ($b.Length -lt 5 -or $b[0] -ne 0x30 -or $b[2] -ne 0x16 -or $b[3] -ge 0x80) { return $null }
  if ((4 + $b[3]) -gt $b.Length) { return $null }
  $name = [Text.Encoding]::GetEncoding(1251).GetString($b, 4, $b[3])
  if ($name -match '[\\\x00-\x1F]') {
    Write-Log -Level 'WARN' -Message ('{0}: имя контейнера отвергнуто — обратный слэш или управляющий символ.' -f (Split-Path -Leaf $Dir))
    return $null
  }
  return $name
}

function Test-NoCertificateCodes {
  <#
    Означают ли коды возврата csptest, что в контейнере нет сертификата.

    Контейнер с одними ключами отвечает SCARD_E_NO_SUCH_CERTIFICATE (0x8010002C) по тому
    типу ключа, который в нём есть, и NTE_KEYSET_NOT_DEF (0x80090019) по остальным (замер
    18.09.2026). Поэтому «сертификата нет» — это когда все попытки вернули один из этих
    двух кодов и хотя бы одна сказала про сертификат прямо. Любой другой код — «прочитать
    не удалось»: заблокированный носитель не должен выглядеть пустым контейнером.
  #>
  param([Parameter(Mandatory=$true)][AllowEmptyCollection()][int[]]$Codes)
  if ($Codes.Count -eq 0) { return $false }
  foreach ($c in $Codes) {
    if ($c -ne $script:ScardNoSuchCertificate -and $c -ne $script:NteKeysetNotDef) { return $false }
  }
  return ($Codes -contains $script:ScardNoSuchCertificate)
}

function Get-ContainerCertificate {
  <#
    Сертификат из контейнера, у которого рядом нет файла .cer. Внутри контейнера
    сертификат замаскирован, поэтому извлекается только через CSP (csptest -expcert).

    Возвращает @{ Cert = <сертификат или $null>; NoCertificate = <$true, когда
    сертификата в контейнере нет> }. Контейнер с одними ключами — обычное дело
    (замер 18.09.2026: 6 из 10 контейнеров рабочего места), и неполнотой разбора
    он не считается: csptest отвечает SCARD_E_NO_SUCH_CERTIFICATE по тому типу
    ключа, который в контейнере есть, и NTE_KEYSET_NOT_DEF по остальным.
    Любой другой код возврата и таймаут остаются «прочитать не удалось».

    Вызов ограничен 10 секундами: КриптоПро может неограниченно ждать носитель,
    и без предела один контейнер съел бы всё время задачи.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Dir,
    [Parameter(Mandatory=$true)][string]$CspTest
  )
  $name = Get-ContainerName -Dir $Dir
  if (-not $name) { return @{ Cert = $null; NoCertificate = $false } }
  $tmp = Join-Path $env:TEMP ('crlcc-{0}.cer' -f [guid]::NewGuid().ToString('N'))
  $codes = New-Object Collections.ArrayList
  try {
    foreach ($kt in 'exchange', 'signature') {
      $a = '-keyset -keytype {0} -container "{1}" -expcert {2}' -f $kt, ($name -replace '"', '\"'), $tmp
      $pr = Start-Process $CspTest -ArgumentList $a -NoNewWindow -PassThru `
              -RedirectStandardOutput ($tmp + '.out') -RedirectStandardError ($tmp + '.err')
      # Windows PowerShell 5.1 loses ExitCode of a -PassThru process whose handle was never read.
      $null = $pr.Handle
      if (-not $pr.WaitForExit(10000)) { try { $pr.Kill() } catch { }; [void]$codes.Add(-1); continue }
      if (Test-Path -LiteralPath $tmp) {
        return @{ Cert = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $tmp); NoCertificate = $false }
      }
      # An unknown exit code is a failure to read, never "no certificate".
      if ($null -eq $pr.ExitCode) { [void]$codes.Add(-1) } else { [void]$codes.Add([int]$pr.ExitCode) }
    }
    return @{ Cert = $null; NoCertificate = (Test-NoCertificateCodes -Codes ([int[]]$codes.ToArray())) }
  } finally {
    foreach ($f in @($tmp, ($tmp + '.out'), ($tmp + '.err'))) {
      if (Test-Path -LiteralPath $f) { try { [IO.File]::Delete($f) } catch { } }
    }
  }
}

function Get-CertificateCdp {
  <#
    Адреса одного сертификата. Пустой результат считается неполнотой: отзыв такого
    сертификата проверить нечем, и прогон не должен выглядеть успешным.
  #>
  param(
    [Parameter(Mandatory=$true)]$Certificate,
    [Parameter(Mandatory=$true)][string]$Label
  )
  $u = @(Get-ChainCdpUrl -Certificate $Certificate)
  if ($u.Count -eq 0) {
    $script:NoCert++
    Write-Log -Level 'WARN' -Message ('{0}: ни одно звено цепочки не несёт точки распространения — отзыв для него не проверить.' -f $Label)
  }
  return $u
}

function Get-CrlDistributionPoints {
  <#
    Возвращает записи @{ File = <имя файла>; Urls = @(...) }.

    Обход идёт по каталогам контейнеров: есть файл .cer — читается он, нет —
    сертификат извлекается из контейнера. Каталог без .cer и без name.key
    контейнером не считается.

    Каждый сертификат, который не удалось прочитать или извлечь, увеличивает
    $script:NoCert, и прогон завершается с кодом 1.
  #>
  param([Parameter(Mandatory=$true)][string]$Root)

  # Счётчик инициализируется здесь: функция вызывается и из тестов.
  $script:NoCert = 0

  $cspTest = Get-CspTestPath
  if ($null -eq $cspTest) {
    Write-Log -Level 'WARN' -Message 'csptest.exe КриптоПро не найден — сертификаты из контейнеров без .cer не извлечь.'
  }

  $dirs = @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-ServicePath -Root $Root -Path $_.FullName) })

  # Файлы .cer в корне каталога и внутри контейнеров. -File обязателен: без него
  # в набор попадают каталоги.
  $cerFiles = @(Get-ChildItem -LiteralPath $Root -File -Filter '*.cer' -Force -ErrorAction SilentlyContinue)
  $toExtract = @()
  foreach ($d in $dirs) {
    $inDir = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -Filter '*.cer' -Force -ErrorAction SilentlyContinue)
    if ($inDir.Count -gt 0) { $cerFiles += $inDir; continue }
    if (Test-Path -LiteralPath (Join-Path $d.FullName 'name.key')) { $toExtract += $d }
  }

  $urls = @(); $fromFile = 0; $fromCont = 0

  foreach ($c in $cerFiles) {
    try {
      $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $c.FullName
      $urls += @(Get-CertificateCdp -Certificate $x -Label $c.Name)
      $fromFile++
    } catch {
      $script:NoCert++
      Write-Log -Level 'WARN' -Message ('Сертификат не разобран: {0}. {1}' -f $c.Name, $_.Exception.Message)
    }
  }

  foreach ($d in $toExtract) {
    if ($null -eq $cspTest) { $script:NoCert++; continue }
    try {
      $x = Get-ContainerCertificate -Dir $d.FullName -CspTest $cspTest
      if ($null -eq $x.Cert) {
        if ($x.NoCertificate) {
          Write-Log -Level 'INFO' -Message ('{0}: в контейнере только ключи, сертификата нет — разбирать нечего.' -f $d.Name)
        } else {
          $script:NoCert++
          Write-Log -Level 'WARN' -Message ('{0}: сертификат из контейнера не извлечён — его точки распространения не найдены.' -f $d.Name)
        }
      } else {
        $urls += @(Get-CertificateCdp -Certificate $x.Cert -Label $d.Name)
        $fromCont++
      }
    } catch {
      $script:NoCert++
      Write-Log -Level 'WARN' -Message ('{0}: извлечение из контейнера сорвалось. {1}' -f $d.Name, $_.Exception.Message)
    }
  }

  Write-Log -Level $(if ($script:NoCert -gt 0) { 'WARN' } else { 'INFO' }) `
    -Message ('Сертификатов для разбора: {0} (файлом {1}, из контейнера {2}); без точек распространения: {3}' -f ($fromFile + $fromCont), $fromFile, $fromCont, $script:NoCert)

  Group-CrlUrlByFile -Urls $urls
}

# -------------------- Загрузка --------------------

function Test-DerContent {
  # CRL в DER начинается с тега SEQUENCE (0x30). Проверка отсеивает HTML-страницы
  # ошибок и заглушки прокси; подлинность списка она не устанавливает.
  param([Parameter(Mandatory=$true)][string]$Path)
  try {
    $fi = Get-Item -LiteralPath $Path
    if ($fi.Length -lt 100) { return $false }
    $fs = [IO.File]::OpenRead($Path)
    try { return ($fs.ReadByte() -eq 0x30) } finally { $fs.Dispose() }
  } catch { return $false }
}

function Get-CrlFromMirrors {
  <#
    Загрузка идёт через BITS: на машине с закрытым исходящим трафиком достаточно
    разрешить выход службе BITS, а не powershell.exe.
  #>
  param(
    [Parameter(Mandatory=$true)][string[]]$Urls,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][int]$TimeoutSec
  )
  # Без явного предела BITS повторяет попытки до 14 суток, и одно недоступное
  # зеркало заняло бы всё время задачи. -RetryInterval не бывает меньше 60 секунд.
  $retryInterval = [Math]::Max(60, [int]$TimeoutSec)

  foreach ($u in $Urls) {
    try {
      [IO.File]::Delete($Destination)   # для отсутствующего файла ничего не делает
      Start-BitsTransfer -Source $u -Destination $Destination `
                         -RetryInterval $retryInterval -RetryTimeout ([int]$TimeoutSec) -ErrorAction Stop
      if (Test-DerContent -Path $Destination) {
        return [pscustomobject]@{ Ok = $true; Url = $u }
      }
      Write-Log -Level 'WARN' -Message ('Скачанное с {0} не похоже на DER — отбрасываю.' -f $u)
      Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
    } catch {
      Write-Log -Level 'WARN' -Message ('Не удалось скачать {0}: {1}' -f $u, $_.Exception.Message)
    }
  }
  return [pscustomobject]@{ Ok = $false; Url = $null }
}

# -------------------- Публикация --------------------

function Move-IntoPlace {
  <#
    Замена опубликованного файла через ReplaceFile: запись в каталоге меняется за
    один шаг, и читающий видит либо прежний файл, либо новый. Move-Item -Force
    поверх существующего файла удаляет его и затем переносит новый, а при открытом
    на чтение файле не срабатывает вовсе; он остаётся запасным путём для реализаций
    SMB без ReplaceFile.
    Третий аргумент — [NullString]::Value: $null PowerShell передаёт пустой строкой.

    ReplaceFile требует права на удаление цели. Пока цель открыта на чтение без
    этого права (соседний публикатор считает её хэш через Get-FileHash, Install-Crl
    копирует), замена получает ERROR_SHARING_VIOLATION. Чтение заканчивается за
    секунды, поэтому замена повторяется. Move-Item в этом случае не поможет: он
    упрётся в ту же блокировку и ответит «файл уже существует».
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Staging,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter()][int]$Attempts = 15,
    [Parameter()][int]$DelaySec = 2
  )
  if (Test-Path -LiteralPath $Target) {
    for ($i = 1; ; $i++) {
      try {
        [IO.File]::Replace($Staging, $Target, [NullString]::Value)
        return
      } catch {
        $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
        if ($e.HResult -ne -2147024864) {   # не ERROR_SHARING_VIOLATION
          Write-Log -Level 'WARN' -Message ('{0}: неделимая замена не удалась ({1}), заменяю переносом.' -f (Split-Path -Leaf $Target), $e.Message)
          break
        }
        if ($i -ge $Attempts) { throw $e }
        Start-Sleep -Seconds $DelaySec
      }
    }
  }
  Move-Item -LiteralPath $Staging -Destination $Target -Force
}

function Get-PublishExitCode {
  <#
      9 — публиковать нечего: каталог публикации пуст или не подтверждён ни один
          список. Прежние копии при этом остаются на месте.
      1 — часть списков не скачалась или у части контейнеров нет сертификата.
      0 — все списки подтверждены и у каждого контейнера есть сертификат.
    Наличие файлов в каталоге успехом не считается: после полного отказа загрузки
    там лежат копии прошлых прогонов.
  #>
  param(
    [Parameter(Mandatory=$true)][int]$Published,
    [Parameter(Mandatory=$true)][int]$Updated,
    [Parameter(Mandatory=$true)][int]$Same,
    [Parameter(Mandatory=$true)][int]$Failed,
    [Parameter(Mandatory=$true)][int]$NoCert
  )
  if ($Published -eq 0)                      { return 9 }
  if ($Failed -eq 0 -and $NoCert -eq 0)      { return 0 }
  if (($Updated + $Same) -eq 0)              { return 9 }
  return 1
}

function Move-RetiredCrl {
  <#
    Снимает с публикации списки, которые больше не встречаются в разборе
    (контейнер удалён или перенесён в KEYS-ARCHIVE), перенося их в _retired.

    Перенос выполняется только на втором прогоне подряд. Контейнер может
    временно отсутствовать (например, во время синхронизации каталога), и такой
    прогон не даёт ни ошибки, ни признака неполноты. Первый прогон ставит в
    _retired отметку <файл>.unreferenced, второй переносит файл; если список
    вернулся в разбор, отметка снимается.

    Install-Crl читает каталог без -Recurse, поэтому перенесённый файл больше не
    устанавливается. Из хранилища на машинах список не удаляется.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$Known
  )
  $retired = Join-Path $Root '_retired'
  foreach ($f in @(Get-ChildItem -LiteralPath $Root -Filter '*.crl' -File -ErrorAction SilentlyContinue)) {
    $mark = Join-Path $retired ($f.Name + '.unreferenced')

    if ($Known -contains $f.Name) {
      if (Test-Path -LiteralPath $mark) {
        Remove-Item -LiteralPath $mark -Force -ErrorAction SilentlyContinue
        Write-Log -Level 'INFO' -Message ('{0}: снова в разборе, отметка кандидата снята.' -f $f.Name)
      }
      continue
    }

    try {
      if (-not (Test-Path -LiteralPath $retired -PathType Container)) { New-Item -ItemType Directory -Path $retired -Force | Out-Null }
      if (-not (Test-Path -LiteralPath $mark)) {
        Set-Content -LiteralPath $mark -Value (Get-Date -Format 'o') -Encoding ASCII
        Write-Log -Level 'INFO' -Message ('{0}: выбыл из разбора, помечен кандидатом — перенесу следующим прогоном, если не вернётся.' -f $f.Name)
        continue
      }
      Move-Item -LiteralPath $f.FullName -Destination (Join-Path $retired $f.Name) -Force
      Remove-Item -LiteralPath $mark -Force -ErrorAction SilentlyContinue
      Write-Log -Level 'OK' -Message ('{0}: выбыл из разбора второй прогон подряд, перенесён в _retired.' -f $f.Name)
    } catch {
      Write-Log -Level 'WARN' -Message ('{0}: выбыл из разбора, но снять с публикации не удалось. {1}' -f $f.Name, $_.Exception.Message)
    }
  }
}

function Remove-StaleStaging {
  <#
    Удаляет временные файлы оборванных прогонов старше часа. Возраст считается по
    более свежей из CreationTime и LastWriteTime: BITS ставит скачанному файлу
    время сервера, и по одной LastWriteTime только что созданный файл другого
    публикатора выглядел бы старым.
  #>
  param([Parameter(Mandatory=$true)][string]$Root)
  try {
    $cutoff = (Get-Date).AddHours(-1)
    foreach ($t in @(Get-ChildItem -LiteralPath $Root -Filter '*.tmp' -File -Force -ErrorAction SilentlyContinue)) {
      $age = @($t.CreationTime, $t.LastWriteTime) | Sort-Object -Descending | Select-Object -First 1
      if ($age -lt $cutoff) {
        try {
          Remove-Item -LiteralPath $t.FullName -Force
          Write-Log -Level 'INFO' -Message ('Убран временный файл прошлого прогона: {0}' -f $t.Name)
        } catch { }
      }
    }
  } catch { }
}

# -------------------- Основной поток --------------------

$exitCode = 0
try {
  Write-Log -Level 'INFO' -Message ('Старт | Версия={0} | Host={1} | RunAs={2}' -f $script:ScriptVersion, $env:COMPUTERNAME, ([Security.Principal.WindowsIdentity]::GetCurrent()).Name)
  Remove-OldLogs -LogDir $LogRoot -RetentionDays $LogRetentionDays

  foreach ($req in 'KeysRoot', 'CrlRoot') {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $req -ValueOnly))) {
      Write-Log -Level 'ERROR' -Message ('Не задан {0}: ни параметром, ни в {1}' -f $req, $SettingsFile)
      exit 2
    }
  }

  if (-not (Test-Path -LiteralPath $KeysRoot -PathType Container)) {
    Write-Log -Level 'ERROR' -Message ('Хранилище ключей недоступно: {0}' -f $KeysRoot)
    exit 8
  }
  if (-not (Test-Path -LiteralPath $CrlRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $CrlRoot -Force | Out-Null
    Write-Log -Level 'OK' -Message ('Создан каталог публикации: {0}' -f $CrlRoot)
  }

  $points = @(Get-CrlDistributionPoints -Root $KeysRoot)
  if (@($points).Count -eq 0) {
    Write-Log -Level 'ERROR' -Message 'В сертификатах не найдено ни одной точки распространения — публиковать нечего.'
    exit 11
  }
  Write-Log -Level 'INFO' -Message ('Различных списков: {0}; адресов всего: {1}' -f @($points).Count, (@($points) | ForEach-Object { @($_.Urls).Count } | Measure-Object -Sum).Sum)

  Remove-StaleStaging -Root $CrlRoot

  $updated = 0; $same = 0; $failed = 0
  $temp = Join-Path $env:TEMP ('crlpub-{0}' -f [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $temp -Force | Out-Null

  try {
    foreach ($p in $points) {
      # Свой try на каждый список: сбой общей папки на одном файле не должен
      # оставлять остальные списки без обновления.
      $staging = $null
      try {
        $tmpFile = Join-Path $temp $p.File
        $res = Get-CrlFromMirrors -Urls $p.Urls -Destination $tmpFile -TimeoutSec $TimeoutSec

        if (-not $res.Ok) {
          $failed++
          $prevCopy = Join-Path $CrlRoot $p.File
          if (Test-Path -LiteralPath $prevCopy) {
            Write-Log -Level 'WARN' -Message ('{0}: ни одно зеркало не ответило, оставляю прежнюю копию от {1:dd.MM.yyyy HH:mm}.' -f $p.File, (Get-Item -LiteralPath $prevCopy).LastWriteTime)
          } else {
            Write-Log -Level 'ERROR' -Message ('{0}: ни одно зеркало не ответило, опубликованной копии нет.' -f $p.File)
          }
          continue
        }

        $target = Join-Path $CrlRoot $p.File
        $isNew  = $true
        if (Test-Path -LiteralPath $target) {
          $isNew = (Get-FileHash -LiteralPath $tmpFile).Hash -ne (Get-FileHash -LiteralPath $target).Hash
        }

        if ($isNew) {
          # Запись под временным именем и замена: читающий не увидит недописанный файл.
          # В имени хост и GUID, потому что публикаторов может быть несколько, а каталог общий.
          $staging = '{0}.{1}.{2}.tmp' -f $target, $env:COMPUTERNAME, [guid]::NewGuid().ToString('N')
          Copy-Item -LiteralPath $tmpFile -Destination $staging -Force
          Move-IntoPlace -Staging $staging -Target $target
          $staging = $null
          $updated++
          Write-Log -Level 'OK' -Message ('{0}: обновлён с {1} ({2:N0} байт)' -f $p.File, $res.Url, (Get-Item -LiteralPath $target).Length)
        } else {
          $same++
          Write-Log -Level 'INFO' -Message ('{0}: не изменился.' -f $p.File)
        }
      } catch {
        $failed++
        Write-Log -Level 'ERROR' -Message ('{0}: публикация не удалась [{1}]: {2}' -f $p.File, $_.Exception.GetType().Name, $_.Exception.Message)
      } finally {
        if ($null -ne $staging) { Remove-Item -LiteralPath $staging -Force -ErrorAction SilentlyContinue }
      }
    }
  } finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
  }

  # Снятие с публикации — только после прогона без ошибок и без неполноты:
  # иначе живой список мог бы выпасть из разбора случайно.
  if ($script:NoCert -eq 0 -and $failed -eq 0) {
    Move-RetiredCrl -Root $CrlRoot -Known @($points | ForEach-Object { $_.File })
  }

  Write-Log -Level $(if ($failed -gt 0 -or $script:NoCert -gt 0) { 'WARN' } else { 'OK' }) -Message ('Готово. Обновлено: {0}; без изменений: {1}; не скачано: {2}; без точек распространения: {3}.' -f $updated, $same, $failed, $script:NoCert)

  $published = @(Get-ChildItem -LiteralPath $CrlRoot -Filter '*.crl' -File -ErrorAction SilentlyContinue).Count
  $exitCode  = Get-PublishExitCode -Published $published -Updated $updated -Same $same -Failed $failed -NoCert $script:NoCert
  if ($exitCode -eq 9) {
    if ($published -eq 0) {
      Write-Log -Level 'ERROR' -Message 'В каталоге публикации нет ни одного списка отзыва.'
    } else {
      Write-Log -Level 'ERROR' -Message ('Не подтверждён ни один список из {0} — прогон результата не дал.' -f $published)
    }
  }

} catch {
  Write-Log -Level 'ERROR' -Message ('Необработанная ошибка [{0}]: {1}' -f $_.Exception.GetType().Name, $_.Exception.Message)
  try { foreach ($l in ($_.ScriptStackTrace -split "`r?`n")) { Write-Log -Level 'ERROR' -Message ('  стек: {0}' -f $l) } } catch { }
  $exitCode = 10
}

exit $exitCode
