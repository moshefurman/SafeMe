<#
.SYNOPSIS
    אורז את סוכן SafeMe למתקין יחיד.

.DESCRIPTION
    מפרסם את השירות, אפליקציית המגש וההסרה, אורז אותם יחד עם סקריפטי
    ההתקנה לארכיב אחד, ומטמיע אותו במתקין.

    התוצאה היא קובץ exe יחיד. שם הקובץ הוא שנושא את אסימון ההתקנה,
    ולכן אין צורך לבנות מתקין נפרד לכל לקוח — השרת משנה את השם בזמן
    ההורדה, וחתימת Authenticode אינה נפגעת משום שהיא מכסה את התוכן.

.EXAMPLE
    .\build\pack.ps1 -Version 1.0.0
#>

[CmdletBinding()]
param(
    [string] $Version = "1.0.0",
    [string] $OutputPath = "",

    # קובץ PEM עם המפתח הציבורי לאימות קודי הסרה.
    #
    # נדרש רק כדי לאפשר התקנה ללא חשבון: שם אין רישום, ולכן אין
    # דרך אחרת להשיג את המפתח. בלעדיו המתקין ייבנה ויעבוד, אבל
    # יסרב לחסום מחשב — וזה נכון, כי חסימה בלי מפתח היא לצמיתות.
    #
    # להשגתו: node server/scripts/export-uninstall-key.ts
    [string] $UninstallKeyPem = ""
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Staging  = Join-Path ([IO.Path]::GetTempPath()) "safeme-pack-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$Payload  = Join-Path $Staging 'payload'
$Installer = Join-Path $RepoRoot 'src\SafeMe.Installer'

if (-not $OutputPath) { $OutputPath = Join-Path $RepoRoot 'artifacts\release' }

Write-Host ""
Write-Host "  אריזת SafeMe $Version" -ForegroundColor Cyan
Write-Host "  $('─' * 42)"
Write-Host ""

# ---------------------------------------------------------------- פרסום

New-Item -ItemType Directory -Force -Path $Payload | Out-Null

# תלוי-runtime, ובמכוון.
#
# הסוכן שוקל כך מגה וקצת במקום 70, וזה ההבדל בין 5 ג'יגה לגרסה
# ל-280 כשמעדכנים אלפי מכשירים. המתקין עצמו עצמאי, כי הוא זה
# שבודק אם סביבת ההרצה קיימת.
$projects = @(
    'src\SafeMe.Service\SafeMe.Service.csproj',
    'src\SafeMe.Guardian\SafeMe.Guardian.csproj',
    'src\SafeMe.TrayApp\SafeMe.TrayApp.csproj',
    'src\SafeMe.Uninstaller\SafeMe.Uninstaller.csproj'
)

foreach ($proj in $projects) {
    $name = Split-Path $proj -Leaf
    Write-Host "  · מפרסם $name"

    dotnet publish (Join-Path $RepoRoot $proj) `
        -c Release -r win-x64 --self-contained false `
        -p:Version=$Version `
        -o $Payload -v q --nologo | Out-Null

    if ($LASTEXITCODE -ne 0) { throw "פרסום $name נכשל." }
}

# סקריפטי ההתקנה נוסעים עם הקבצים. ההיגיון נשאר במקום אחד, ולא
# משוכפל בין הסקריפט למתקין.
Copy-Item (Join-Path $RepoRoot 'deploy\install.ps1')   $Payload
Copy-Item (Join-Path $RepoRoot 'deploy\uninstall.ps1') $Payload

<#
    ------------------------------------------------------- סגירת -Force

    הסרה כפויה קיימת בפיתוח ואינה נארזת.

    היא עוקפת את כל תהליך ההסרה: בלי קוד, בלי מוקד, בלי
    אימות. כל ההקשחה — הרשאות שירות, הגנת רישום, שני שומרים,
    ובחירת ההורה בין הסרה עצמית להסרה דרך המוקד — אינה נוגעת בה.

    האריזה נכשלת אם הסימן לא נמצא או אם ההחלפה לא תפסה.
    סימן ששינה את שמו ואיש לא נכשל עליו הוא בדיוק הדרך שבה
    דלת אחורית נשארת פתוחה בלי שאיש התכוון.
#>

$uninstallPath = Join-Path $Payload 'uninstall.ps1'
$uninstallText = Get-Content $uninstallPath -Raw

$marker = '$ForceAllowed = $true # SAFEME-FORCE-ALLOWED'

if (-not $uninstallText.Contains($marker)) {
    throw ('סימן סגירת -Force לא נמצא ב-uninstall.ps1. האריזה נעצרת, ' +
        'כדי שהמתקין לא ייארז עם הסרה כפויה פתוחה. יש להחזיר את השורה: ' + $marker)
}

$uninstallText = $uninstallText.Replace($marker, '$ForceAllowed = $false # בנייה רשמית')

Set-Content -Path $uninstallPath -Value $uninstallText -Encoding utf8

# אימות בקריאה חוזרת. כתיבה שהצליחה ולא תפסה גרועה מכשל גלוי.
if ((Get-Content $uninstallPath -Raw).Contains('$ForceAllowed = $true')) {
    throw 'סגירת -Force לא תפסה. האריזה נעצרת.'
}

Write-Host '  · הסרה כפויה נסגרה במטען' -ForegroundColor Green

# ---------------------------------------------------------------- מפתח ההסרה

$settingsPath = Join-Path $Payload 'appsettings.json'

if ($UninstallKeyPem) {
    if (-not (Test-Path $UninstallKeyPem)) {
        throw "קובץ המפתח לא נמצא: $UninstallKeyPem"
    }

    # Get-Content -Raw מחזיר null על קובץ ריק, ו-.Trim() עליו זורק
    # "You cannot call a method on a null-valued expression" — הודעה
    # שאינה מרמזת על הסיבה. וקובץ ריק הוא בדיוק מה שנוצר כשהפניית
    # הפלט הצליחה אבל הסקריפט שמאחוריה נכשל.
    $pem = Get-Content $UninstallKeyPem -Raw

    if ([string]::IsNullOrWhiteSpace($pem)) {
        throw @"
קובץ המפתח ריק: $UninstallKeyPem

זה קורה כשהפניית הפלט יצרה את הקובץ אבל הייצוא עצמו נכשל.
יש להריץ שוב ולקרוא את הודעת השגיאה:
  node server/scripts/export-uninstall-key.ts > uninstall.pem
"@
    }

    $pem = $pem.Trim()

    # בדיקה אמיתית ולא רק התאמת תבנית.
    #
    # המפתח הזה קובע אם מחשב שנחסם יוכל אי פעם להשתחרר, ולכן
    # "מכיל BEGIN PUBLIC KEY" אינו מספיק: קובץ קטוע, קידוד שגוי,
    # או העתקה חלקית — כולם עוברים את התבנית ונכשלים בשימוש.
    #
    # הפענוח מוודא שהגוף הוא Base64 תקין ושאורכו סביר ל-SubjectPublicKeyInfo
    # של RSA-2048. תקלה כאן מתגלה באריזה, ולא על מחשב חסום.

    if ($pem -notmatch '-----BEGIN PUBLIC KEY-----') {
        throw "הקובץ אינו מפתח ציבורי ב-PEM: $UninstallKeyPem"
    }

    if ($pem -notmatch '-----END PUBLIC KEY-----') {
        throw "המפתח קטוע — חסרה שורת הסיום: $UninstallKeyPem"
    }

    $body = ($pem -replace '-----[A-Z ]+-----', '') -replace '\s', ''

    try {
        $der = [Convert]::FromBase64String($body)
    }
    catch {
        throw "גוף המפתח אינו Base64 תקין. ייתכן שהקובץ נכתב בקידוד שגוי: $UninstallKeyPem"
    }

    if ($der.Length -lt 240 -or $der.Length -gt 600) {
        throw "אורך המפתח חריג ($($der.Length) בתים). צפוי כ-294 עבור RSA-2048."
    }

    $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
    $settings.Server.UninstallPublicKeyPem = $pem
    $settings | ConvertTo-Json -Depth 10 | Out-File $settingsPath -Encoding utf8

    Write-Host "  · מפתח ההסרה הוטבע ($($der.Length) בתים). התקנה ללא חשבון אפשרית." -ForegroundColor Green
}
else {
    Write-Host "  · ללא מפתח הסרה מוטבע. התקנה ללא חשבון תסורב." -ForegroundColor Yellow
}

$fileCount = (Get-ChildItem $Payload -File -Recurse).Count
$rawSize   = (Get-ChildItem $Payload -File -Recurse | Measure-Object Length -Sum).Sum

Write-Host "  · $fileCount קבצים, $([Math]::Round($rawSize / 1MB, 1)) מגה"

# ---------------------------------------------------------------- ארכיב

$zip = Join-Path $Installer 'payload.zip'

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $Payload '*') -DestinationPath $zip -CompressionLevel Optimal

Write-Host "  · המטען דחוס ל-$([Math]::Round((Get-Item $zip).Length / 1MB, 1)) מגה"

# ---------------------------------------------------------------- המתקין

try {
    Write-Host "  · בונה את המתקין"

    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

    dotnet publish (Join-Path $Installer 'SafeMe.Installer.csproj') `
        -c Release -p:Version=$Version `
        -o $OutputPath -v q --nologo | Out-Null

    if ($LASTEXITCODE -ne 0) { throw "בניית המתקין נכשלה." }
}
finally {
    # הארכיב אינו נשמר במאגר. השארתו הייתה מכניסה בינאריות לגיט
    # ומשבשת את הבנייה הרגילה בפעם הבאה.
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    Remove-Item $Staging -Recurse -Force -ErrorAction SilentlyContinue
}

$exe = Join-Path $OutputPath 'SafeMe-Setup.exe'

if (-not (Test-Path $exe)) { throw "לא נוצר קובץ מתקין." }

$size = (Get-Item $exe).Length
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash

Write-Host ""
Write-Host "  המתקין מוכן." -ForegroundColor Green
Write-Host ""
Write-Host "    קובץ  : $exe"
Write-Host "    גודל  : $([Math]::Round($size / 1MB, 1)) מגה"
Write-Host "    SHA256: $hash"
Write-Host ""
Write-Host "  הערכים האלה נכנסים ל-agent_releases בשרת." -ForegroundColor DarkGray
Write-Host "  הקובץ אינו חתום — Windows SmartScreen יזהיר בהתקנה." -ForegroundColor DarkYellow
Write-Host ""

# פלט מכונה, לשימוש בשחרור אוטומטי
[PSCustomObject]@{
    Version = $Version
    Path    = $exe
    Bytes   = $size
    Sha256  = $hash
} | ConvertTo-Json -Compress | Out-File (Join-Path $OutputPath 'release.json') -Encoding utf8
