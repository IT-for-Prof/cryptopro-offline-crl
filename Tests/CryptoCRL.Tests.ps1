#requires -Version 5.1
<#
.SYNOPSIS
  Проверки функций Publish-Crl.ps1 и Install-Crl.ps1: служебные каталоги, имя
  контейнера, разбор CDP, группировка зеркал, признак DER, состояние установки,
  замена файла, уборка, снятие с публикации и код возврата.

  Функции извлекаются из скриптов разбором AST, основной блок не исполняется:
  тест ничего не скачивает, не публикует и не трогает хранилище mCA.

.NOTES
  itforprof.com by Konstantin Tyutyunnik

  Запуск:  powershell -NoProfile -ExecutionPolicy Bypass -File Tests\CryptoCRL.Tests.ps1
  Код возврата: 0 — все проверки прошли; 1 — есть падения.
  Зависимостей нет (Pester не требуется).
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# --- загрузка тестируемых функций из скриптов через AST (без основного блока) ---
# Функция только ВЫДАЁТ исходник: dot-source обязан произойти в области видимости
# самого теста, иначе функции осядут в кадре загрузчика и исчезнут вместе с ним.
function Get-FunctionSource {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string[]]$Names
  )
  # ProviderPath, а не Path: у UNC-пути `.Path` даёт форму с префиксом
  # провайдера, которую ParseFile не принимает. Локально разницы нет.
  $full = (Resolve-Path -LiteralPath $Path).ProviderPath
  $tokens = $null; $errs = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errs)
  if ($errs) { throw "Боевой скрипт не парсится: $full — $($errs[0].Message)" }
  $funcs = @($ast.FindAll({
        param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Names -contains $n.Name
      }, $true))
  $found   = @($funcs | ForEach-Object { $_.Name })
  $missing = @($Names | Where-Object { $found -notcontains $_ })
  if ($missing.Count -gt 0) { throw "В $full не найдены функции: $($missing -join ', ')" }
  return (($funcs | ForEach-Object { $_.Extent.Text }) -join "`r`n")
}

. ([scriptblock]::Create((Get-FunctionSource -Path (Join-Path $PSScriptRoot '..\Publish-Crl.ps1') `
        -Names 'Test-ServicePath', 'Test-DerContent', 'Move-IntoPlace', 'Remove-StaleStaging', 'Get-PublishExitCode',
               'Get-CdpUrl', 'Group-CrlUrlByFile', 'Get-ContainerName', 'Move-RetiredCrl', 'Test-NoCertificateCodes')))
. ([scriptblock]::Create((Get-FunctionSource -Path (Join-Path $PSScriptRoot '..\Install-Crl.ps1') `
        -Names 'Test-CrlAlreadyInstalled')))

# заглушка логгера: тестируем поведение, а не строки лога
function Write-Log { param($Level, $Message) }

# --- крошечный assert-харнесс (без Pester) ---
$script:pass = 0; $script:fail = 0
function It($name, [scriptblock]$body) {
  try { & $body; $script:pass++; Write-Host ("  PASS  " + $name) -ForegroundColor Green }
  catch { $script:fail++; Write-Host ("  FAIL  " + $name + "  -> " + $_.Exception.Message) -ForegroundColor Red }
}
function Eq($actual, $expected, $msg) { if ("$actual" -ne "$expected") { throw "${msg}: ожидалось [$expected], получено [$actual]" } }
function True($cond, $msg) { if (-not $cond) { throw $msg } }

$sandbox = Join-Path $env:TEMP ('crltests-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $sandbox | Out-Null
try {
  # ================= Test-ServicePath =================
  # Смысл проверки — якорь от корня. Ошибка здесь тихая: выпадет живой сертификат,
  # его точка распространения не попадёт в публикацию, и подпись начнёт ждать сеть.
  Write-Host "`nTest-ServicePath" -ForegroundColor Cyan
  $root = 'C:\ProgramData\Crypto Pro\KEYS'
  It 'BACKUP у корня — служебный'        { Eq (Test-ServicePath -Root $root -Path "$root\BACKUP\HOST\1\a.cer") $true 'result' }
  It 'KEYS-ARCHIVE у корня — служебный'  { Eq (Test-ServicePath -Root $root -Path "$root\KEYS-ARCHIVE\old\a.cer") $true 'result' }
  It 'BACKUP внутри контейнера — НЕ служебный (якорь от корня)' {
    Eq (Test-ServicePath -Root $root -Path "$root\user2026.000\BACKUP\a.cer") $false 'result'
  }
  It 'обычный контейнер — не служебный'  { Eq (Test-ServicePath -Root $root -Path "$root\user2026.000\a.cer") $false 'result' }
  It 'BACKUPS не считается BACKUP (нужен разделитель)' {
    Eq (Test-ServicePath -Root $root -Path "$root\BACKUPS\a.cer") $false 'result'
  }
  It 'хвостовой слэш в корне не меняет классификацию' {
    Eq (Test-ServicePath -Root "$root\" -Path "$root\BACKUP\a.cer") $true 'result'
  }
  It 'регистр каталога не важен' { Eq (Test-ServicePath -Root $root -Path "$root\backup\a.cer") $true 'result' }
  # Обход идёт по каталогам, поэтому путь приходит без завершающего разделителя.
  It 'путь к самому каталогу, без завершающего разделителя — служебный' {
    Eq (Test-ServicePath -Root $root -Path "$root\BACKUP") $true 'result'
  }
  It 'обычный контейнер как каталог — не служебный' {
    Eq (Test-ServicePath -Root $root -Path "$root\user2026") $false 'result'
  }
  # Служебные каталоги тома: если каталог контейнеров — корень диска, корзина
  # вернула бы в публикацию точки распространения удалённого контейнера.
  It 'System Volume Information — служебный' {
    Eq (Test-ServicePath -Root $root -Path "$root\System Volume Information") $true 'result'
  }
  It 'корзина тома — служебная' {
    Eq (Test-ServicePath -Root $root -Path "$root\`$RECYCLE.BIN\S-1-5-21-1\a.cer") $true 'result'
  }
  It 'BACKUPS не считается BACKUP и как каталог' {
    Eq (Test-ServicePath -Root $root -Path "$root\BACKUPS") $false 'result'
  }

  # ================= Get-ContainerName =================
  # Без верного имени сертификат из контейнера не извлечётся, и его точки
  # распространения не попадут в публикацию. Образцы повторяют формат name.key.
  Write-Host "`nGet-ContainerName" -ForegroundColor Cyan
  function New-NameKey($dir, [byte[]]$bytes) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $dir 'name.key'), $bytes)
    return $dir
  }
  $nkRoot = Join-Path $sandbox 'nk'
  It 'латинское имя читается ровно по объявленной длине' {
    $name = '12345678@2026-01-01-Ivanov Ivan Ivanovich - Copy'
    $v = [Text.Encoding]::GetEncoding(1251).GetBytes($name)
    $d = New-NameKey (Join-Path $nkRoot 'lat') ([byte[]]@(0x30, ($v.Length + 2), 0x16, $v.Length) + $v)
    Eq (Get-ContainerName -Dir $d) $name 'имя'
  }
  It 'кириллица декодируется cp1251, а не ASCII' {
    $name = 'ООО "Ромашка" 2025-2026'
    $v = [Text.Encoding]::GetEncoding(1251).GetBytes($name)
    $d = New-NameKey (Join-Path $nkRoot 'cyr') ([byte[]]@(0x30, ($v.Length + 2), 0x16, $v.Length) + $v)
    Eq (Get-ContainerName -Dir $d) $name 'имя'
  }
  It 'хвост за пределами структуры в имя не попадает' {
    # у части контейнеров за строкой лежит hex-остаток и байты 0xFF
    $name = 'ООО "Ромашка" 2025-2026'
    $v = [Text.Encoding]::GetEncoding(1251).GetBytes($name)
    $tail = [Text.Encoding]::ASCII.GetBytes('ffad918416a3') + (,[byte]0xFF * 240)
    $d = New-NameKey (Join-Path $nkRoot 'tail') ([byte[]]@(0x30, ($v.Length + 2), 0x16, $v.Length) + $v + $tail)
    Eq (Get-ContainerName -Dir $d) $name 'имя без хвоста'
  }
  # Имя уходит в командную строку процесса под SYSTEM, а name.key пишет пользователь.
  # Обратный слэш ломает экранирование кавычки: \" превращается в \\", и разбор
  # командной строки закрывает аргумент, а остаток имени становится новыми ключами.
  It 'имя с обратным слэшем отвергается — подстановка аргументов невозможна' {
    $name = 'X\" -expcert C:\evil.cer'
    $v = [Text.Encoding]::GetEncoding(1251).GetBytes($name)
    $d = New-NameKey (Join-Path $nkRoot 'inj') ([byte[]]@(0x30, ($v.Length + 2), 0x16, $v.Length) + $v)
    True ($null -eq (Get-ContainerName -Dir $d)) 'имя с обратным слэшем не должно возвращаться'
  }
  It 'имя с управляющим символом отвергается' {
    $v = [Text.Encoding]::GetEncoding(1251).GetBytes("A`r`nB")
    $d = New-NameKey (Join-Path $nkRoot 'ctl') ([byte[]]@(0x30, ($v.Length + 2), 0x16, $v.Length) + $v)
    True ($null -eq (Get-ContainerName -Dir $d)) 'имя с CR/LF не должно возвращаться'
  }
  It 'кавычки в имени остаются законными — их экранирование работает' {
    $name = 'ООО "Ромашка" 2025-2026'
    $v = [Text.Encoding]::GetEncoding(1251).GetBytes($name)
    $d = New-NameKey (Join-Path $nkRoot 'ok') ([byte[]]@(0x30, ($v.Length + 2), 0x16, $v.Length) + $v)
    Eq (Get-ContainerName -Dir $d) $name 'имя'
  }
  It 'name.key отсутствует — null, без исключения' {
    New-Item -ItemType Directory -Force -Path (Join-Path $nkRoot 'empty') | Out-Null
    True ($null -eq (Get-ContainerName -Dir (Join-Path $nkRoot 'empty'))) 'ожидался null'
  }
  It 'не DER-структура — null, а не мусорное имя' {
    $d = New-NameKey (Join-Path $nkRoot 'junk') ([byte[]]@(0x41, 0x42, 0x43, 0x44, 0x45))
    True ($null -eq (Get-ContainerName -Dir $d)) 'ожидался null'
  }
  It 'длинная форма длины не поддерживается — null, а не обрезанное имя' {
    $d = New-NameKey (Join-Path $nkRoot 'long') ([byte[]]@(0x30, 0x84, 0x16, 0x81, 0x41, 0x42))
    True ($null -eq (Get-ContainerName -Dir $d)) 'ожидался null'
  }
  It 'объявленная длина больше файла — null, без выхода за границы' {
    $d = New-NameKey (Join-Path $nkRoot 'over') ([byte[]]@(0x30, 0x40, 0x16, 0x3E, 0x41, 0x42))
    True ($null -eq (Get-ContainerName -Dir $d)) 'ожидался null'
  }

  # ================= Get-CdpUrl =================
  # Сертификат подделываем утиной типизацией: настоящий X509Certificate2 в тесте
  # взять негде, а функции от него нужны ровно Extensions[].Oid.Value и Format().
  function New-FakeCert($cdpText) {
    $exts = @()
    if ($null -ne $cdpText) {
      $e = [pscustomobject]@{ Oid = [pscustomobject]@{ Value = '2.5.29.31' } }
      $e | Add-Member -MemberType ScriptMethod -Name Format -Value { param($m) $cdpText }.GetNewClosure()
      $exts += $e
    }
    return [pscustomobject]@{ Extensions = $exts; Thumbprint = 'FAKE' }
  }
  Write-Host "`nGet-CdpUrl" -ForegroundColor Cyan
  It 'адрес извлекается из текста расширения' {
    $u = @(Get-CdpUrl -Certificate (New-FakeCert "[1]Точка распространения CRL`r`n     Имя точки распространения:`r`n          Полное имя:`r`n               URL=http://cdp.tax.gov.ru/cdp/23f0da4a.crl`r`n"))
    Eq $u.Count 1 'число адресов'
    Eq $u[0] 'http://cdp.tax.gov.ru/cdp/23f0da4a.crl' 'адрес'
  }
  It 'несколько адресов в одном расширении — все' {
    $u = @(Get-CdpUrl -Certificate (New-FakeCert "URL=http://a.ru/cdp/guc2022.crl`r`nURL=http://b.ru/cdp/guc2022.crl"))
    Eq $u.Count 2 'число адресов'
  }
  It 'хвостовые скобка, кавычка, запятая и точка с запятой отрезаются' {
    $u = @(Get-CdpUrl -Certificate (New-FakeCert "(http://a.ru/x.crl) `"http://b.ru/y.crl`" http://c.ru/z.crl, http://d.ru/w.crl;"))
    Eq (($u -join ' ')) 'http://a.ru/x.crl http://b.ru/y.crl http://c.ru/z.crl http://d.ru/w.crl' 'адреса без мусора'
  }
  It 'ldap-адрес рядом с http игнорируется (качать по ldap не умеем)' {
    $u = @(Get-CdpUrl -Certificate (New-FakeCert "URL=ldap:///CN=x?certificateRevocationList`r`nURL=http://a.ru/x.crl"))
    Eq $u.Count 1 'число адресов'
    Eq $u[0] 'http://a.ru/x.crl' 'адрес'
  }
  It 'расширения CDP нет — пусто, без исключения' {
    Eq (@(Get-CdpUrl -Certificate (New-FakeCert $null)).Count) 0 'число адресов'
  }

  # ================= Group-CrlUrlByFile =================
  # Список листа и список головного УЦ — разные файлы, и оба нужны: без второго
  # цепочка без доступа в интернет не строится (0x80092013 на звене УЦ). Зеркала
  # одного файла сводятся в одну запись.
  Write-Host "`nGroup-CrlUrlByFile" -ForegroundColor Cyan
  It 'адреса листа и УЦ дают ДВЕ записи, а не одну' {
    $g = @(Group-CrlUrlByFile -Urls @(
        'http://cdp.tax.gov.ru/cdp/23f0da4a.crl',   # лист: список ФНС
        'http://company.rt.ru/cdp/guc2022.crl'))    # звено УЦ: список ГУЦ
    Eq $g.Count 2 'число списков'
    Eq (($g.File | Sort-Object) -join ',') '23f0da4a.crl,guc2022.crl' 'имена файлов'
  }
  It 'три адреса одного файла — один список с тремя зеркалами' {
    $g = @(Group-CrlUrlByFile -Urls @(
        'http://c0000-app005/cdp/23f0da4a.crl',
        'http://cdp.tax.gov.ru/cdp/23f0da4a.crl',
        'http://pki.tax.gov.ru/cdp/23f0da4a.crl'))
    Eq $g.Count 1 'число списков'
    Eq @($g[0].Urls).Count 3 'число зеркал'
  }
  It 'порядок зеркал сохраняется — в нём же их перебирает загрузчик' {
    $g = @(Group-CrlUrlByFile -Urls @('http://first.ru/x.crl', 'http://second.ru/x.crl'))
    Eq ($g[0].Urls -join ',') 'http://first.ru/x.crl,http://second.ru/x.crl' 'порядок'
  }
  It 'повторный адрес не удваивает зеркало (один файл встречен у нескольких сертификатов)' {
    $g = @(Group-CrlUrlByFile -Urls @('http://a.ru/guc2022.crl', 'http://a.ru/guc2022.crl'))
    Eq @($g[0].Urls).Count 1 'число зеркал'
  }
  It 'адрес без имени файла отбрасывается' {
    Eq (@(Group-CrlUrlByFile -Urls @('http://a.ru/cdp/')).Count) 0 'число списков'
  }
  It 'пустой вход — пусто, без исключения' {
    Eq (@(Group-CrlUrlByFile -Urls @()).Count) 0 'число списков'
  }
  It 'записи отсортированы по имени файла — состав публикации не зависит от порядка разбора' {
    $g = @(Group-CrlUrlByFile -Urls @('http://a.ru/z.crl', 'http://a.ru/a.crl', 'http://a.ru/m.crl'))
    Eq ($g.File -join ',') 'a.crl,m.crl,z.crl' 'порядок записей'
  }

  # ================= Test-DerContent =================
  Write-Host "`nTest-DerContent" -ForegroundColor Cyan
  $der = Join-Path $sandbox 'good.crl'
  [IO.File]::WriteAllBytes($der, ([byte[]]@(0x30, 0x82) + (New-Object byte[] 200)))
  It 'DER-последовательность (0x30) — принимается' { Eq (Test-DerContent -Path $der) $true 'result' }

  $html = Join-Path $sandbox 'proxy.crl'
  [IO.File]::WriteAllText($html, ('<html><body>' + ('x' * 300) + '</body></html>'))
  It 'HTML-заглушка прокси — отбраковывается' { Eq (Test-DerContent -Path $html) $false 'result' }

  $tiny = Join-Path $sandbox 'tiny.crl'
  [IO.File]::WriteAllBytes($tiny, ([byte[]]@(0x30) + (New-Object byte[] 10)))
  It 'файл короче 100 байт — отбраковывается даже с верным первым байтом' { Eq (Test-DerContent -Path $tiny) $false 'result' }

  It 'отсутствующий файл — отбраковывается без исключения' {
    Eq (Test-DerContent -Path (Join-Path $sandbox 'nope.crl')) $false 'result'
  }

  # Известное ограничение, зафиксировано намеренно: ASCII '0' — это тот же байт 0x30,
  # поэтому текст, начинающийся с нуля, проверку проходит. Дешёвый фильтр ловит
  # HTML-страницы ошибок, а не подделку; подлинность даёт подпись УЦ.
  $ascii = Join-Path $sandbox 'ascii.crl'
  [IO.File]::WriteAllText($ascii, ('0' + ('1' * 300)))
  It "текст с ASCII '0' проходит фильтр — граница проверки зафиксирована" { Eq (Test-DerContent -Path $ascii) $true 'result' }

  # ================= Test-CrlAlreadyInstalled =================
  Write-Host "`nTest-CrlAlreadyInstalled" -ForegroundColor Cyan
  $h = 'A1B2C3'
  $st = Join-Path $sandbox 'state.sha256'
  It 'файла состояния нет — не установлен' {
    Eq (Test-CrlAlreadyInstalled -StateFile (Join-Path $sandbox 'absent.sha256') -Hash $h) $false 'result'
  }
  It 'отпечаток совпадает — установлен' {
    Set-Content -LiteralPath $st -Value $h -Encoding ASCII
    Eq (Test-CrlAlreadyInstalled -StateFile $st -Hash $h) $true 'result'
  }
  It 'хвостовой перевод строки не мешает совпадению' {
    [IO.File]::WriteAllText($st, "$h`r`n")
    Eq (Test-CrlAlreadyInstalled -StateFile $st -Hash $h) $true 'result'
  }
  It 'другой отпечаток — не установлен' {
    Set-Content -LiteralPath $st -Value 'FFFFFF' -Encoding ASCII
    Eq (Test-CrlAlreadyInstalled -StateFile $st -Hash $h) $false 'result'
  }
  It 'пустой файл состояния — не установлен (лишняя установка безобидна)' {
    [IO.File]::WriteAllText($st, '')
    Eq (Test-CrlAlreadyInstalled -StateFile $st -Hash $h) $false 'result'
  }

  # ================= Move-IntoPlace =================
  Write-Host "`nMove-IntoPlace" -ForegroundColor Cyan
  $pub = Join-Path $sandbox 'pub'; New-Item -ItemType Directory -Force -Path $pub | Out-Null
  It 'цели нет — файл встаёт на место, временного не остаётся' {
    $s = Join-Path $pub 'a.crl.tmp'; $t = Join-Path $pub 'a.crl'
    Set-Content -LiteralPath $s -Value 'new' -Encoding ASCII
    Move-IntoPlace -Staging $s -Target $t
    Eq ((Get-Content -LiteralPath $t -Raw).Trim()) 'new' 'содержимое'
    True (-not (Test-Path -LiteralPath $s)) 'временный файл должен исчезнуть'
  }
  It 'цель есть — содержимое заменяется, временного не остаётся' {
    $s = Join-Path $pub 'b.crl.tmp'; $t = Join-Path $pub 'b.crl'
    Set-Content -LiteralPath $t -Value 'old' -Encoding ASCII
    Set-Content -LiteralPath $s -Value 'new' -Encoding ASCII
    Move-IntoPlace -Staging $s -Target $t
    Eq ((Get-Content -LiteralPath $t -Raw).Trim()) 'new' 'содержимое'
    True (-not (Test-Path -LiteralPath $s)) 'временный файл должен исчезнуть'
  }
  It 'резервная копия рядом с целью не создаётся' {
    $s = Join-Path $pub 'c.crl.tmp'; $t = Join-Path $pub 'c.crl'
    Set-Content -LiteralPath $t -Value 'old' -Encoding ASCII
    Set-Content -LiteralPath $s -Value 'new' -Encoding ASCII
    Move-IntoPlace -Staging $s -Target $t
    Eq (@(Get-ChildItem -LiteralPath $pub -Filter 'c.crl*' -File).Count) 1 'файлов c.crl*'
  }
  # Соседний публикатор считает хэш опубликованного файла: Get-FileHash открывает
  # его через OpenRead, без права на удаление, и ReplaceFile получает «файл занят».
  It 'цель открыта на чтение и вскоре освобождается — замена проходит после ожидания' {
    $s = Join-Path $pub 'd.crl.tmp'; $t = Join-Path $pub 'd.crl'
    Set-Content -LiteralPath $t -Value 'old' -Encoding ASCII
    Set-Content -LiteralPath $s -Value 'new' -Encoding ASCII
    $opened = New-Object Threading.ManualResetEventSlim $false
    $reader = [powershell]::Create().AddScript({
        param($path, $signal)
        $h = [IO.File]::OpenRead($path); $signal.Set()
        Start-Sleep -Milliseconds 1500
        $h.Dispose()
      }).AddArgument($t).AddArgument($opened)
    $job = $reader.BeginInvoke()
    try {
      True ($opened.Wait(10000)) 'читатель не открыл файл'
      Move-IntoPlace -Staging $s -Target $t -Attempts 10 -DelaySec 1
      Eq ((Get-Content -LiteralPath $t -Raw).Trim()) 'new' 'содержимое'
      True (-not (Test-Path -LiteralPath $s)) 'временный файл должен исчезнуть'
    } finally { [void]$reader.EndInvoke($job); $reader.Dispose() }
  }
  It 'цель занята дольше ожидания — ошибка «файл занят», прежний файл цел' {
    $s = Join-Path $pub 'e.crl.tmp'; $t = Join-Path $pub 'e.crl'
    Set-Content -LiteralPath $t -Value 'old' -Encoding ASCII
    Set-Content -LiteralPath $s -Value 'new' -Encoding ASCII
    $h = [IO.File]::OpenRead($t)
    $err = $null
    try { Move-IntoPlace -Staging $s -Target $t -Attempts 2 -DelaySec 0 } catch { $err = $_ } finally { $h.Dispose() }
    True ($null -ne $err) 'ожидалось исключение'
    $e = $err.Exception; while ($e.InnerException) { $e = $e.InnerException }
    Eq $e.HResult -2147024864 'HResult (ERROR_SHARING_VIOLATION)'
    Eq ((Get-Content -LiteralPath $t -Raw).Trim()) 'old' 'содержимое'
  }

  # ================= Remove-StaleStaging =================
  # Уборка удаляет только старые временные файлы: свежий может принадлежать
  # публикации, которая идёт сейчас на другом хосте.
  Write-Host "`nRemove-StaleStaging" -ForegroundColor Cyan
  $sw = Join-Path $sandbox 'sweep'; New-Item -ItemType Directory -Force -Path $sw | Out-Null
  function New-Aged($dir, $name, $hoursAgo) {
    $p = Join-Path $dir $name
    Set-Content -LiteralPath $p -Value 'x' -Encoding ASCII
    $i = Get-Item -LiteralPath $p
    $i.LastWriteTime = (Get-Date).AddHours(-1 * $hoursAgo)
    $i.CreationTime  = (Get-Date).AddHours(-1 * $hoursAgo)
    return $p
  }
  It 'старый временный файл убирается' {
    $old = New-Aged $sw 'x.crl.HOST.aaa.tmp' 5
    Remove-StaleStaging -Root $sw
    True (-not (Test-Path -LiteralPath $old)) 'старый .tmp должен исчезнуть'
  }
  It 'старая LastWriteTime при свежей CreationTime — не трогаем (BITS ставит время сервера УЦ)' {
    $p = Join-Path $sw 'w.crl.HOST.ccc.tmp'
    Set-Content -LiteralPath $p -Value 'x' -Encoding ASCII
    (Get-Item -LiteralPath $p).LastWriteTime = (Get-Date).AddHours(-9)
    Remove-StaleStaging -Root $sw
    True (Test-Path -LiteralPath $p) 'только что созданный .tmp трогать нельзя, каким бы ни было LastWriteTime'
  }
  It 'свежий временный файл не трогаем (чужая идущая публикация)' {
    $fresh = New-Aged $sw 'y.crl.HOST.bbb.tmp' 0
    Remove-StaleStaging -Root $sw
    True (Test-Path -LiteralPath $fresh) 'свежий .tmp трогать нельзя'
  }
  It 'опубликованный список не трогаем ни при каком возрасте' {
    $crl = New-Aged $sw 'z.crl' 999
    Remove-StaleStaging -Root $sw
    True (Test-Path -LiteralPath $crl) 'уборка не должна касаться .crl'
  }
  It 'отсутствующий каталог — без исключения' {
    Remove-StaleStaging -Root (Join-Path $sandbox 'nowhere')
    True $true 'исключения быть не должно'
  }

  # ================= Move-RetiredCrl =================
  # Контейнер, временно отсутствующий во время синхронизации каталога, не даёт ни
  # ошибки, ни признака неполноты. Поэтому список снимается только на втором
  # прогоне подряд.
  Write-Host "`nMove-RetiredCrl" -ForegroundColor Cyan
  function New-Pub($name) {
    $p = Join-Path $sandbox ('pub-' + $name)
    New-Item -ItemType Directory -Force -Path $p | Out-Null
    return $p
  }
  It 'первый прогон только помечает — файл остаётся на месте' {
    $p = New-Pub 'first'
    Set-Content -LiteralPath (Join-Path $p 'gone.crl') -Value 'x' -Encoding ASCII
    Move-RetiredCrl -Root $p -Known @('live.crl')
    True (Test-Path -LiteralPath (Join-Path $p 'gone.crl')) 'первый прогон переносить не должен'
    True (Test-Path -LiteralPath (Join-Path $p '_retired\gone.crl.unreferenced')) 'должна появиться отметка кандидата'
  }
  It 'второй прогон подряд переносит в _retired и убирает отметку' {
    $p = New-Pub 'second'
    Set-Content -LiteralPath (Join-Path $p 'gone.crl') -Value 'x' -Encoding ASCII
    Move-RetiredCrl -Root $p -Known @()
    Move-RetiredCrl -Root $p -Known @()
    True (-not (Test-Path -LiteralPath (Join-Path $p 'gone.crl'))) 'второй прогон должен перенести'
    True (Test-Path -LiteralPath (Join-Path $p '_retired\gone.crl')) 'файл должен оказаться в _retired'
    True (-not (Test-Path -LiteralPath (Join-Path $p '_retired\gone.crl.unreferenced'))) 'отметка должна быть снята'
  }
  It 'вернувшийся в разбор список снимает свою отметку и не переносится' {
    $p = New-Pub 'return'
    Set-Content -LiteralPath (Join-Path $p 'flaky.crl') -Value 'x' -Encoding ASCII
    Move-RetiredCrl -Root $p -Known @()              # окно синхронизации: не увидели
    Move-RetiredCrl -Root $p -Known @('flaky.crl')   # вернулся
    Move-RetiredCrl -Root $p -Known @()              # снова не увидели — счёт начат заново
    True (Test-Path -LiteralPath (Join-Path $p 'flaky.crl')) 'живой список переносить нельзя'
    True (Test-Path -LiteralPath (Join-Path $p '_retired\flaky.crl.unreferenced')) 'отметка ставится заново, а не продолжает прежнюю'
  }
  It 'востребованный список не трогаем ни на одном прогоне' {
    $p = New-Pub 'live'
    Set-Content -LiteralPath (Join-Path $p 'live.crl') -Value 'x' -Encoding ASCII
    Move-RetiredCrl -Root $p -Known @('live.crl')
    Move-RetiredCrl -Root $p -Known @('live.crl')
    True (Test-Path -LiteralPath (Join-Path $p 'live.crl')) 'востребованный список должен остаться'
    True (-not (Test-Path -LiteralPath (Join-Path $p '_retired'))) '_retired не должен создаваться без нужды'
  }
  It 'уже перенесённый список повторно не обрабатывается' {
    $p = New-Pub 'idem'
    Set-Content -LiteralPath (Join-Path $p 'gone.crl') -Value 'x' -Encoding ASCII
    Move-RetiredCrl -Root $p -Known @(); Move-RetiredCrl -Root $p -Known @()
    Move-RetiredCrl -Root $p -Known @()
    Eq (@(Get-ChildItem -LiteralPath (Join-Path $p '_retired') -Filter '*.crl' -File).Count) 1 'копий в _retired'
  }
  It 'пустой набор известных списков при пустом каталоге — без исключения' {
    Move-RetiredCrl -Root (New-Pub 'empty') -Known @()
    True $true 'исключения быть не должно'
  }

  # ================= Test-NoCertificateCodes =================

  Write-Host "`nTest-NoCertificateCodes" -ForegroundColor Cyan
  $script:ScardNoSuchCertificate = -2146435028
  $script:NteKeysetNotDef = -2146893799
  It 'контейнер с одними ключами: нет сертификата и нет второго ключа' {
    True (Test-NoCertificateCodes -Codes @(-2146435028, -2146893799)) 'должно считаться контейнером без сертификата'
  }
  It 'оба типа ключа отвечают «нет сертификата»' {
    True (Test-NoCertificateCodes -Codes @(-2146435028, -2146435028)) 'должно считаться контейнером без сертификата'
  }
  It 'только «нет такого ключа» — про сертификат никто не сказал' {
    True (-not (Test-NoCertificateCodes -Codes @(-2146893799, -2146893799))) 'не должно считаться контейнером без сертификата'
  }
  It 'заблокированный носитель пустым контейнером не выглядит' {
    True (-not (Test-NoCertificateCodes -Codes @(-2146435028, 1))) 'посторонний код — прочитать не удалось'
  }
  It 'пустой список кодов ничего не утверждает' {
    True (-not (Test-NoCertificateCodes -Codes @())) 'без кодов вывода нет'
  }

  # ================= Get-PublishExitCode =================
  # Полный отказ загрузки должен давать ненулевой код, даже когда в каталоге
  # лежат копии прошлых прогонов.
  Write-Host "`nGet-PublishExitCode" -ForegroundColor Cyan
  It 'всё скачано — 0'  { Eq (Get-PublishExitCode -Published 5 -Updated 3 -Same 2 -Failed 0 -NoCert 0) 0 'код' }
  It 'ничего не менялось, ошибок нет — 0' { Eq (Get-PublishExitCode -Published 5 -Updated 0 -Same 5 -Failed 0 -NoCert 0) 0 'код' }
  It 'часть списков не скачалась — 1'     { Eq (Get-PublishExitCode -Published 5 -Updated 2 -Same 2 -Failed 1 -NoCert 0) 1 'код' }
  It 'не подтверждён ни один список при полном каталоге — 9, а не 0' {
    Eq (Get-PublishExitCode -Published 5 -Updated 0 -Same 0 -Failed 5 -NoCert 0) 9 'код'
  }
  It 'каталог публикации пуст — 9' { Eq (Get-PublishExitCode -Published 0 -Updated 0 -Same 0 -Failed 4 -NoCert 0) 9 'код' }
  It 'зелёный ноль возможен только при нулевом числе ошибок' {
    foreach ($u in 0, 1, 3) { foreach ($s in 0, 1, 3) { foreach ($fl in 1, 2, 5) {
          True ((Get-PublishExitCode -Published 5 -Updated $u -Same $s -Failed $fl -NoCert 0) -ne 0) "u=$u s=$s f=$fl не должен давать 0"
        } } }
  }
  # Контейнер без сертификата — неполное покрытие, и код возврата должен это показать.
  It 'контейнер без сертификата — не 0, даже когда всё скачалось' {
    Eq (Get-PublishExitCode -Published 5 -Updated 0 -Same 5 -Failed 0 -NoCert 1) 1 'код'
  }
  It 'зелёный ноль невозможен ни при какой неполноте покрытия' {
    foreach ($u in 0, 1, 3) { foreach ($s in 0, 1, 3) { foreach ($nc in 1, 2, 7) {
          True ((Get-PublishExitCode -Published 5 -Updated $u -Same $s -Failed 0 -NoCert $nc) -ne 0) "u=$u s=$s nocert=$nc не должен давать 0"
        } } }
  }
  It 'пустой каталог публикации важнее неполноты покрытия — 9' {
    Eq (Get-PublishExitCode -Published 0 -Updated 0 -Same 0 -Failed 0 -NoCert 3) 9 'код'
  }

  # ================= CryptoCRL.local.psd1 =================
  # Скрипты запускаются целиком в отдельном процессе из каталога-песочницы, чтобы
  # $PSScriptRoot указывал туда же, где лежит файл настроек. Пути выбраны так,
  # что прогон останавливается раньше любой загрузки или установки.
  Write-Host "`nCryptoCRL.local.psd1" -ForegroundColor Cyan
  function Invoke-InSandbox($name, $script, $settings, [string[]]$arguments) {
    $dir = Join-Path $sandbox ('run-' + $name)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "..\$script") -Destination $dir
    if ($null -ne $settings) {
      [IO.File]::WriteAllText((Join-Path $dir 'CryptoCRL.local.psd1'), $settings, (New-Object Text.UTF8Encoding $true))
    }
    $ps = Join-Path $PSHOME 'powershell.exe'
    # stderr дочернего процесса при 'Stop' стал бы ошибкой NativeCommandError
    & {
      $ErrorActionPreference = 'Continue'
      & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $dir $script) -LogRoot (Join-Path $dir 'log') @arguments *> $null
    }
    return $LASTEXITCODE
  }
  $missing = Join-Path $sandbox 'no-such-dir'
  It 'Install-Crl: CrlRoot не задан нигде — 2' {
    Eq (Invoke-InSandbox 'i-none' 'Install-Crl.ps1' $null @()) 2 'код'
  }
  It 'Install-Crl: CrlRoot из файла настроек — дальше проверки параметров' {
    $rc = Invoke-InSandbox 'i-file' 'Install-Crl.ps1' "@{ CrlRoot = '$missing' }" @('-StateRoot', (Join-Path $sandbox 'st'))
    True (@(8, 13) -contains $rc) "ожидался 8 (каталог недоступен) или 13 (нет certmgr), получено $rc"
  }
  It 'Install-Crl: параметр важнее файла' {
    $rc = Invoke-InSandbox 'i-param' 'Install-Crl.ps1' "@{ CrlRoot = '' }" @('-CrlRoot', $missing, '-StateRoot', (Join-Path $sandbox 'st'))
    True (@(8, 13) -contains $rc) "ожидался 8 или 13, получено $rc"
  }
  It 'Install-Crl: ключ Publish-Crl в общем файле не мешает' {
    $rc = Invoke-InSandbox 'i-foreign' 'Install-Crl.ps1' "@{ CrlRoot = '$missing'; KeysRoot = 'X:\' }" @('-StateRoot', (Join-Path $sandbox 'st'))
    True (@(8, 13) -contains $rc) "ожидался 8 или 13, получено $rc"
  }
  It 'Install-Crl: нечитаемый файл настроек — 2' {
    Eq (Invoke-InSandbox 'i-bad' 'Install-Crl.ps1' '@{ CrlRoot = ' @()) 2 'код'
  }
  It 'Publish-Crl: KeysRoot не задан — 2' {
    Eq (Invoke-InSandbox 'p-none' 'Publish-Crl.ps1' "@{ CrlRoot = '$missing' }" @()) 2 'код'
  }
  It 'Publish-Crl: оба пути из файла, каталога ключей нет — 8' {
    Eq (Invoke-InSandbox 'p-file' 'Publish-Crl.ps1' "@{ KeysRoot = '$missing'; CrlRoot = '$missing' }" @()) 8 'код'
  }
}
finally {
  Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("ИТОГ: PASS=$script:pass  FAIL=$script:fail") -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
