# SafeMe — מסמך אפיון ארכיטקטורה מלא

> גרסה 1.0 · סוכן אכיפת גלישה בטוחה ל‑Windows
> פלטפורמה: .NET 9 · Windows 10 1809+ / Windows 11 / Windows Server 2019+

---

## 1. תקציר מנהלים

**SafeMe** הוא סוכן אבטחה (Security Agent) לתחנות Windows, שתפקידו להבטיח שהמחשב מחובר
**אך ורק** לחיבור אינטרנט מסונן ומאושר (NetFree, אתרוג, רימון, וכד'). הסוכן:

1. **מזהה** את ספק הסינון הפעיל בעזרת מספר וקטורי בדיקה בלתי תלויים.
2. **מבקר (Audits)** את איכות הסינון בפועל מול חוקים דינמיים שמגיעים מהשרת.
3. **אוכף** מדיניות רשת ברמת הליבה באמצעות Windows Filtering Platform (WFP).
4. **מדווח** לשרת ניהול מרכזי בפעימה (Heartbeat) קבועה.
5. **מוגן מפני עקיפה** באמצעות Watchdog כפול והסרה מבוקרת ב‑Challenge/Response.

### 1.1 עקרונות מנחים (חובה)

| עיקרון | משמעות מימושית |
|---|---|
| **הסכמה מדעת** | ההתקנה מציגה בפירוש מה נאכף. אין הסתרה, אין rootkit, אין הזרקת קוד לתהליכים. |
| **נראות מלאה** | אייקון מגש קבוע + חלון סטטוס מפורט. המשתמש תמיד רואה מה חסום ולמה. |
| **מסלול יציאה מובטח** | קיים תמיד נתיב הסרה חוקי (קוד מהמוקד). קוד חירום אופליין מונע "נעילת לבנה". |
| **Fail‑Safe ולא Fail‑Open** | אובדן קשר לשרת ← מצב חסד (Grace) מוגדר, לא פתיחה מיידית. |
| **מינימום הרשאות** | רק ה‑Service רץ כ‑SYSTEM. ה‑TrayApp רץ כמשתמש רגיל וללא הרשאות אכיפה. |
| **ללא התחמקות מזיהוי** | הסוכן אינו מסתיר את עצמו מ‑Task Manager, מ‑Defender או מכלי ניהול. |

---

## 2. מבנה הפתרון (Solution Layout)

```
SafeMe.sln
├── src/
│   ├── SafeMe.Core           (net9.0)          — לוגיקה משותפת, ללא תלות ב‑OS
│   │   ├── Models/            מודלים וחוזי נתונים (DTOs)
│   │   ├── Policy/            מודל המדיניות הדינמית מהשרת
│   │   ├── Security/          HWID, Base32, Challenge‑Response, HMAC/RSA
│   │   ├── Ipc/               חוזי הודעות בין ה‑Service ל‑UI
│   │   └── Abstractions/      ממשקים (IAuditProbe, IEnforcementEngine, ...)
│   │
│   ├── SafeMe.Service        (net9.0-windows)  — שירות Windows, רץ כ‑SYSTEM
│   │   ├── Wfp/               עטיפת WFP ב‑P/Invoke + מנהל אכיפה
│   │   ├── Audit/             גששי בדיקה: Root CA, זהות רשת, HTTP/AI
│   │   ├── Net/               לקוח HTTP מול שרת הניהול
│   │   ├── Ipc/               שרת Named Pipes
│   │   ├── Watchdog/          השגחה על TrayApp + הפעלה בסשן המשתמש
│   │   ├── State/             אחסון מקומי מוצפן (DPAPI‑Machine)
│   │   └── Workers/           לולאות רקע (Audit, Heartbeat, Watchdog)
│   │
│   ├── SafeMe.TrayApp        (net9.0-windows, WPF) — אייקון מגש + חלון סטטוס
│   └── SafeMe.Uninstaller    (net9.0-windows, WPF) — מסך אתגר/תגובה להסרה
│
├── tools/SafeMe.CodeGen      — כלי CLI לצד השרת/מוקד: יצירת קוד תגובה
├── tests/SafeMe.Tests        — בדיקות יחידה (xUnit)
└── deploy/                   — סקריפטי התקנה, רישום שירות, ACL
```

### 2.1 חלוקת תהליכים והרשאות

| תהליך | הקשר הרצה | הרשאות | תפקיד |
|---|---|---|---|
| `SafeMe.Service.exe` | `NT AUTHORITY\SYSTEM`, Session 0 | מלאות | אכיפה, בדיקות, שרת IPC, תקשורת לשרת |
| `SafeMe.TrayApp.exe` | משתמש מחובר, Session N | רגילות | תצוגה בלבד + Watchdog קליינט |
| `SafeMe.Uninstaller.exe` | Elevated (Admin) | UAC | מסך אתגר/תגובה; **אינו** מאמת בעצמו |

> **הערה קריטית:** אימות קוד ההסרה מתבצע **בתוך ה‑Service** (SYSTEM), לא ב‑UI.
> ה‑Uninstaller הוא רק "טופס" ששולח את הקוד ב‑IPC ומקבל אישור/דחייה.
> כך ניתוק או החלפה של ה‑UI אינם עוקפים את האימות.

---

## 3. מנגנון IPC

### 3.1 בחירת טכנולוגיה

| חלופה | יתרונות | חסרונות | החלטה |
|---|---|---|---|
| **Named Pipes + JSON** | מובנה ב‑Windows, ACL מדויק ברמת SID, ללא פורט TCP, עובד מ‑Session 0 ל‑Session N | פרוטוקול ידני | ✅ **נבחר** |
| gRPC over TCP | חוזים חזקים | פותח פורט מקומי ← משטח תקיפה, צריך אימות נוסף | ❌ |
| gRPC over Named Pipe | חוזים חזקים + ללא פורט | תלות ב‑Grpc.Net ומורכבות | 🔸 חלופה עתידית |

**החלטה:** Named Pipe בשם `\\.\pipe\SafeMe.Agent.v1`, פרוטוקול **JSON תחום‑שורה** (NDJSON), UTF‑8.

### 3.2 אבטחת הצינור (Pipe ACL)

```
SYSTEM                  → FullControl
BUILTIN\Administrators  → FullControl
BUILTIN\Users           → Read | Write | Synchronize   (בקשות סטטוס בלבד)
```

* פקודות רגישות (`UNINSTALL_*`, `POLICY_REFRESH`, `LOCKOUT_*`) נדחות אלא אם
  לקוח הצינור **מורם (Elevated)** — נבדק על ידי בדיקת ה‑Token של תהליך הלקוח
  (`GetNamedPipeClientProcessId` ← `OpenProcessToken` ← `TokenElevation`).
* כל בקשה נושאת `RequestId` (GUID) לצורך התאמה ולוגים.

### 3.3 חוזי הודעות

```jsonc
// בקשה
{ "id":"<guid>", "op":"GET_STATUS", "payload": { } }

// תשובה
{ "id":"<guid>", "ok":true, "error":null, "payload": { } }
```

| `op` | דורש הרמה | Payload בקשה | Payload תשובה |
|---|---|---|---|
| `PING` | לא | — | `{version, uptimeSec}` |
| `GET_STATUS` | לא | — | `StatusSnapshot` |
| `RUN_AUDIT_NOW` | לא | — | `AuditReport` |
| `GET_POLICY` | לא | — | `PolicyBundle` (מסונן) |
| `UNINSTALL_CHALLENGE` | כן | `{reason}` | `{challenge, expiresUtc}` |
| `UNINSTALL_VERIFY` | כן | `{challenge, response}` | `{granted, token, lockoutUntil, attemptsLeft}` |
| `LOCKOUT_STATE` | כן | — | `{active, until, reason}` |

---

## 4. פרוטוקול שרת–לקוח (Server API)

תעבורה: **HTTPS בלבד**, `Content-Type: application/json`.
אימות: `Authorization: Bearer <DeviceToken>` + `X-SafeMe-Hwid: <hwid>`.
כל תשובה מהשרת שמכילה מדיניות **חתומה ב‑RSA‑PSS/SHA‑256** — הלקוח מאמת לפני יישום.

### 4.1 `POST /api/v1/enroll` — רישום ראשוני

```jsonc
// בקשה
{
  "hwid": "F3A9...E21",
  "machineName": "PC-YOSSI",
  "osVersion": "10.0.26100",
  "agentVersion": "1.0.0",
  "licenseKey": "SAFE-XXXX-XXXX-XXXX",
  "installId": "<guid>"
}
// תשובה
{
  "deviceId": "<guid>",
  "deviceToken": "<jwt>",
  "policyEtag": "W/\"a91f\"",
  "uninstallKeyMode": "Rsa",
  "serverPublicKeyPem": "-----BEGIN PUBLIC KEY-----...",
  "deviceSecret": null
}
```

### 4.2 `GET /api/v1/policy` — משיכת חבילת מדיניות

תומך `If-None-Match` ← `304 Not Modified`.

```jsonc
{
  "version": 42,
  "issuedUtc": "2026-08-25T09:00:00Z",
  "ttlMinutes": 240,
  "graceMinutes": 720,
  "signature": "<base64 RSA-PSS על ה-JSON הקנוני>",

  "providers": [
    {
      "id": "netfree",
      "displayName": "נטפרי",
      "trustLevel": "High",
      "rootCa": {
        "thumbprints": ["9A1B..."],
        "subjectPatterns": ["CN=NetFree*"],
        "required": true
      },
      "network": {
        "asns": [61098],
        "cidrs": ["185.32.0.0/16"],
        "reverseDnsPatterns": ["*.netfree.link", "*.nf.local"]
      },
      "httpMarkers": {
        "url": "http://detect.safeme.local/probe",
        "headers": { "X-NetFree": "*" },
        "bodyContains": ["netfree"]
      }
    }
  ],

  "contentProbes": [
    {
      "id": "adult-01",
      "category": "Adult",
      "url": "https://probe.safeme.io/c/adult-01",
      "method": "GET",
      "timeoutMs": 6000,
      "expect": "Blocked",
      "blockedIf": {
        "statusIn": [403, 451, 302],
        "bodyContains": ["חסום", "blocked"],
        "redirectHostIn": ["block.netfree.link"]
      },
      "weight": 30,
      "severity": "Critical"
    }
  ],

  "aiProbes": [
    { "id":"chatgpt", "host":"chat.openai.com",  "expect":"Blocked", "weight":15 },
    { "id":"claude",  "host":"claude.ai",        "expect":"Blocked", "weight":15 },
    { "id":"gemini",  "host":"gemini.google.com","expect":"Blocked", "weight":15 }
  ],

  "imageProbes": [
    { "id":"blur-01", "url":"https://probe.safeme.io/img/1.jpg",
      "expectTransformed": true, "originalSha256":"ab12...", "weight":10 }
  ],

  "enforcement": {
    "mode": "Enforce",
    "minScoreForGreen": 85,
    "minScoreForYellow": 60,
    "onRedAction": "Lockout",
    "lockoutGraceSeconds": 120,
    "allowedNetworks": {
      "wifiSsids": ["HOME-NETFREE"],
      "cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
      "requireProvider": ["netfree", "etrog", "rimon"]
    },
    "alwaysAllow": {
      "hosts": ["api.safeme.io"],
      "ips": ["203.0.113.10/32"],
      "ports": [443],
      "allowDns": true,
      "allowDhcp": true,
      "allowLoopback": true
    },
    "schedules": [
      { "id":"night", "days":["Sun","Mon","Tue","Wed","Thu"],
        "from":"23:30", "to":"05:30", "action":"BlockAll" }
    ]
  }
}
```

### 4.3 `POST /api/v1/heartbeat` — פעימה (כל 3 דקות)

```jsonc
// בקשה
{
  "hwid":"F3A9...", "agentVersion":"1.0.0", "policyVersion":42,
  "sentUtc":"2026-08-25T09:03:00Z", "sequence": 1183,
  "status":"Safe",
  "score": 92,
  "enforcement":"Enforce",
  "activeAdapters":[{"name":"Wi-Fi","ssid":"HOME-NETFREE","gateway":"192.168.1.1"}],
  "publicIp":"185.32.10.4",
  "detectedProvider":"netfree",
  "failedProbes":["ai-gemini"],
  "tamperEvents":[{"kind":"ServiceStopAttempt","utc":"...","detail":"..."}],
  "wfpFilterCount": 27,
  "uptimeSec": 84120
}
// תשובה
{
  "ok": true,
  "serverUtc": "2026-08-25T09:03:00Z",
  "policyEtag": "W/\"a91f\"",
  "commands": [
    { "id":"<guid>", "type":"RefreshPolicy" },
    { "id":"<guid>", "type":"Lockout", "args":{"minutes":30,"reason":"בקשת הורה"} },
    { "id":"<guid>", "type":"RunAudit" },
    { "id":"<guid>", "type":"ReleaseLockout" }
  ]
}
```

### 4.4 נקודות קצה נוספות

| נתיב | תיאור |
|---|---|
| `POST /api/v1/audit` | דוח ביקורת מפורט (כל הגששים והראיות) |
| `POST /api/v1/events` | אירועי חבלה/ניתוק בעדיפות גבוהה |
| `POST /api/v1/uninstall/challenge` | (מוקד בלבד) המרת אתגר לקוד תגובה |
| `GET  /api/v1/health` | בדיקת זמינות ללא אימות |

### 4.5 Dead Man's Switch (צד שרת)

| מצב | תנאי | פעולה |
|---|---|---|
| `Healthy` | פעימה אחרונה < 10 דק' | — |
| `Late` | 10–30 דק' | סימון בלוח הבקרה |
| `Missing` | 30–120 דק' | התראת Email |
| `Offline` | > 120 דק' | Email + SMS לאחראי |
| `Tampered` | דיווח `tamperEvents` או ירידה חדה בציון | התראה מיידית + SMS |

חלון שקט (Quiet Window) מוגדר למקרי כיבוי מתוכנן; הלקוח שולח
`POST /events {kind:"GracefulShutdown"}` לפני כיבוי מסודר כדי למנוע התראת שווא.

---

## 5. מנוע הביקורת (Audit Engine)

הביקורת מורכבת מ‑**גששים (Probes)** בלתי‑תלויים. כל גשש מחזיר `ProbeResult`
(`Pass` / `Fail` / `Inconclusive` + משקל + ראיות). המנוע מצרף לציון 0–100.

### 5.1 זיהוי ספק סינון — 4 וקטורים בלתי תלויים

| וקטור | שיטה | עמידות לזיוף |
|---|---|---|
| **Root CA** | סריקת `LocalMachine\Root` — התאמת Thumbprint/Subject לרשימת השרת | בינונית (ניתן להסיר, אך אז ה‑TLS של הספק נשבר) |
| **Reverse DNS** | `Dns.GetHostEntryAsync(publicIp)` והתאמת תבנית | בינונית |
| **טווחי IP / ASN** | ה‑IP הציבורי מול CIDR/ASN מהמדיניות | גבוהה |
| **כותרות HTTP** | בקשת בדיקה + כותרות מזהות של הספק | בינונית |

**חוק ההכרעה:** נדרשות **לפחות 2 התאמות** מווקטורים שונים כדי לקבוע `detectedProvider`
ברמת ביטחון `High`. התאמה בודדת ← `Medium`. אפס ← `None` (חיבור לא מזוהה).

### 5.2 בדיקת תוכן

לכל `contentProbe` מבוצעת בקשת HTTP עם `AllowAutoRedirect=false` ו‑Timeout קצר.
הגשש מסווג `Blocked` אם מתקיים אחד מהבאים:

* קוד סטטוס ברשימת `statusIn`
* הפניה ל‑Host ברשימת `redirectHostIn`
* הגוף מכיל אחת ממחרוזות `bodyContains`
* כשל TLS מסוג `RemoteCertificateNameMismatch` מול CA של הספק (חסימה ב‑SNI)
* `NameResolutionFailure` או תשובת DNS = `0.0.0.0` / IP של דף חסימה

**חשוב:** כתובות הגששים הן **דומיינים ניטרליים בשליטת השרת** (`probe.safeme.io/c/<id>`)
שמחזירים תוכן מסומן. הסוכן **אינו** ניגש לתוכן פוגעני בפועל.

### 5.3 בדיקת פלטפורמות AI

בדיקת נגישות ל‑`chat.openai.com`, `claude.ai`, `gemini.google.com`, `copilot.microsoft.com`
ברמת TCP + TLS ClientHello בלבד (ללא שליחת בקשה) — מספיק כדי לקבוע אם הסינון חוסם.

### 5.4 בדיקת טשטוש תמונות

הורדת תמונת ייחוס ידועה וחישוב SHA‑256.
אם ה‑hash שונה מהמקור ← הספק ביצע טרנספורמציה (טשטוש) ← `Pass`.
זהה למקור ← הסינון אינו מטשטש ← `Fail` במשקל שהוגדר.

### 5.5 חישוב הציון והסטטוס

```
score = 100 × Σ(weight_i × pass_i) / Σ(weight_i)
```

כשל בגשש `severity=Critical` מוריד את הציון לתקרה של 40 ללא קשר לשאר.

| ציון | ספק מזוהה | סטטוס | צבע מגן |
|---|---|---|---|
| ≥ `minScoreForGreen` (85) | כן, High | `Safe` | 🟢 ירוק |
| ≥ `minScoreForYellow` (60) | כן / Medium | `LowFilter` | 🟡 צהוב |
| < 60 | לא | `Unfiltered` | 🔴 אדום |
| — | נעילה פעילה | `Blocked` | ⚫ אפור |
| — | אין נתונים / השירות מושבת | `Unknown` | ⚪ אפור בהיר |

### 5.6 מחווני הסטטוס במסך

הסטטוס מוצג בשני מקומות, ולא באחד:

| מחוון | תפקיד |
|---|---|
| **תג צף** בפינת המסך | המחוון הראשי. גלוי תמיד, בלי שום פעולה |
| אייקון במגש המערכת | גיבוי, ותפריט פעולות |

**למה נדרש תג ולא רק אייקון מגש:** ב‑Windows 11 אייקוני מגש מוסתרים
כברירת מחדל מאחורי חץ. משתמש שצריך ללחוץ כדי לראות אם הוא מוגן —
אינו יודע אם הוא מוגן. זה סותר את עקרון הנראות המלאה שבסעיף 1.1.

התג נצמד לפינה נבחרת (ארבע אפשרויות), ניתן לגרירה בין הפינות,
ואפשר לכווץ אותו למגן בלבד. **אי אפשר לסגור אותו לגמרי** — Alt+F4
מכווץ במקום לסגור. זו פשרה מכוונת בין נראות לשליטת המשתמש.

צבע המגן וצבע מסגרת התג נקבעים לפי הסטטוס, כך שהמצב נקלט בראייה
היקפית עוד לפני קריאת הטקסט.

**מקור אחד לצורה:** `ShieldRenderer` מצייר את המגן, ומשמש את שלושת
הצרכנים — אייקון קובצי ההרצה, אייקון המגש, והתג הצף. הקובץ מקושר
גם לכלי `SafeMe.AssetGen` שמייצר את קובצי ה‑ICO, ולכן הצורה אינה
יכולה להתפצל בין המקומות.

---

## 6. ארכיטקטורת האכיפה — WFP

### 6.1 למה WFP ולא Windows Firewall API

| שיקול | WFP (`fwpuclnt.dll`) | `INetFwPolicy2` (COM) |
|---|---|---|
| עדיפות מול חוקי המשתמש | **SubLayer ייעודי במשקל גבוה** | מתערבב עם חוקי המשתמש |
| עמידות לשינוי ידני | לא נראה ב‑`wf.msc`, מוגן על ידי Provider | ניתן למחיקה מה‑UI |
| שרידות אתחול (Boot‑time) | `FWPM_FILTER_FLAG_BOOTTIME` | לא נתמך |
| דיוק (app id, port, addr, flags) | מלא | חלקי |

### 6.2 היררכיית האובייקטים

```
Provider   {8F2A6C31-...}  "SafeMe Agent"   [PERSISTENT]
  └─ SubLayer {4D1E77A5-...} "SafeMe Enforcement"  weight = 0xFF00
        ├─ Filter: BlockAll     (ALE_AUTH_CONNECT_V4/V6)  weight  100  action=BLOCK
        ├─ Filter: AllowLoopback(FLAGS ∋ IS_LOOPBACK)      weight 3000  action=PERMIT
        ├─ Filter: AllowAgentApp(ALE_APP_ID = Service.exe) weight 2500  action=PERMIT
        ├─ Filter: AllowServer  (REMOTE_ADDRESS ∈ svcIps)  weight 2000  action=PERMIT
        ├─ Filter: AllowDns     (PROTOCOL=UDP, PORT=53)    weight 1900  action=PERMIT
        ├─ Filter: AllowDhcp    (PORT 67/68)               weight 1900  action=PERMIT
        └─ Filter: AllowNet[i]  (REMOTE_ADDRESS ∈ cidr)    weight 1000  action=PERMIT
```

* **סשן דינמי** (`FWPM_SESSION_FLAG_DYNAMIC`) לחוקים זמניים ← נמחקים אוטומטית אם ה‑Service קורס
  (Fail‑Safe: אין "נעילת לבנה" אם השירות מת).
* **סשן פרסיסטנטי** לחוקים שחייבים לשרוד אתחול — בשימוש רק עבור `BlockAll` בלוח זמנים
  מרוחק, ותמיד עם `AllowServer` פרסיסטנטי לצידו.
* כל שינוי מתבצע ב‑**טרנזקציה** (`FwpmTransactionBegin0` / `Commit0` / `Abort0`) — אטומי.

### 6.3 מצבי אכיפה

| מצב | תיאור | חוקי WFP |
|---|---|---|
| `Monitor` | דיווח בלבד | אין |
| `Warn` | התראה במגש, ללא חסימה | אין |
| `Enforce` | חסימת רשתות שאינן ברשימה הלבנה | Block כללי + Allow לרשימה |
| `Lockout` (חירום) | חסימת **כל** היוצא פרט לשרת SafeMe | Block כללי + Allow לשרת/DNS/Loopback |
| `Scheduled Block` | חסימה בחלון זמן מהשרת | זהה ל‑Lockout, עם TTL |

### 6.4 בטיחות

* **Watchdog Timer בליבת ה‑Service:** אם לא התקבלה פעימה מוצלחת מהשרת במשך
  `graceMinutes` **ולא** בוצע Lockout יזום — הנעילה משתחררת אוטומטית (מניעת מצב "אין דרך חזרה").
* לפני כל Lockout: יישוב DNS של `api.safeme.io` ל‑IP‑ים בפועל ו‑pin שלהם ב‑Allow‑list,
  בנוסף לכתובות הסטטיות מהמדיניות.
* אימות תקופתי (כל 30 שניות) שכל החוקים עדיין קיימים ב‑BFE; אם נמחקו — בנייה מחדש + `tamperEvent`.

---

## 7. Watchdog כפול

```
          ┌───────────────────────────┐
          │  SafeMe.Service (SYSTEM)  │
          │  ─ SCM Recovery: restart  │
          └────────┬──────────────────┘
      כל 5 שניות:  │  WTSEnumerateSessions ← לכל סשן פעיל
                   │  אם אין SafeMe.TrayApp.exe ← CreateProcessAsUser
                   ▼
          ┌───────────────────────────┐
          │  SafeMe.TrayApp (User)    │
          │  כל 10 שניות:              │
          │  ServiceController.Status │
          │  != Running ← StartService│
          └───────────────────────────┘
```

שכבות הגנה נוספות:

1. **SCM Recovery Actions** — `sc failure SafeMeAgent reset= 0 actions= restart/5000/restart/5000/restart/10000`
2. **Service SID + `SERVICE_CONFIG_LAUNCH_PROTECTED`** (`SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT` — דורש קוד חתום)
3. **ACL על מפתחות הרישום והתיקיות** — כתיבה ל‑SYSTEM + Administrators בלבד.
4. **Scheduled Task** גיבוי (`\SafeMe\Guardian`) שרץ כל 15 דק' ומוודא שהשירות רשום ורץ.
5. כל ניסיון עצירה או מחיקה נרשם כ‑`tamperEvent` ונשלח מיידית לשרת בעדיפות גבוהה.

---

## 8. מזהה חומרה (HWID)

```
HWID = Base32Crockford( SHA256(
        MachineGuid                       (HKLM\SOFTWARE\Microsoft\Cryptography)
     || Win32_ComputerSystemProduct.UUID  (SMBIOS)
     || Win32_BaseBoard.SerialNumber
     || Win32_Processor.ProcessorId
   ) )[0..25]
```

נורמליזציה: trim, upper, והתעלמות מערכים ריקים או מסוג `"To be filled by O.E.M."`.
שינוי כרטיס רשת או דיסק **אינו** משנה את ה‑HWID (בכוונה — למניעת ניתוקי רישוי שווא).
החלפת לוח אם משנה את ה‑HWID ← נדרש שחרור רישיון מהמוקד.

---

## 9. הסרה מבוקרת — Challenge / Response

### 9.1 זרימה

```
[משתמש] מפעיל SafeMe.Uninstaller (UAC)
   │
   ├─► IPC: UNINSTALL_CHALLENGE
   │        Service בונה אתגר, שומר Nonce במצב מוגן, מחזיר מחרוזת
   │
   ├─► המסך מציג:   K7M2QX-4BNP9L-3WZC8T-...   (36 תווים, 6 קבוצות)
   │   המשתמש מתקשר למוקד או נכנס לפורטל
   │
   ├─► [שרת] מאמת זהות + מדיניות ארגונית ← מייצר תגובה
   │        Rsa : חתימת RSA-PSS/SHA-256 על האתגר (Base64, ~344 תווים)
   │        Hmac: HMAC-SHA256(deviceSecret, ctx||challenge)[0..14] ← Base32 (24 תווים)
   │
   ├─► המשתמש מקליד או מדביק את התגובה
   │
   └─► IPC: UNINSTALL_VERIFY  ← אימות **בתוך ה-Service**:
            1. פענוח האתגר + בדיקת CRC
            2. התאמת HWID
            3. חלון זמן: |now − issued| ≤ 30 דק' (+ סבילות שעון ±5 דק')
            4. Nonce תואם לאתגר הפתוח ולא נוצל
            5. אימות חתימה/HMAC בזמן קבוע (constant-time)
            6. Rate limit: 3 כשלונות ← נעילה 15 דק' (מצטבר ×2 עד 4 שעות)
            ← הצלחה: הסרת כל חוקי WFP, כתיבת UninstallToken, עצירת Watchdog,
                      דיווח לשרת, אישור ל-msiexec להמשיך.
```

### 9.2 מבנה האתגר (22 בתים ← Base32, 36 תווים)

| היסט | גודל | שדה |
|---|---|---|
| 0 | 1 | `version` (=1) |
| 1 | 1 | `flags` (bit0 = מצב RSA, bit1 = חירום אופליין) |
| 2 | 8 | `hwidHash` = SHA256(HWID)[0..7] |
| 10 | 4 | `issuedUnixMinutes` (UInt32 LE) |
| 14 | 6 | `nonce` (CSPRNG) |
| 20 | 2 | `crc16` (CCITT על בתים 0..19) |

תצוגה: `Base32Crockford` ללא תווים מבלבלים (I, L, O, U), בקבוצות של 6 עם מקפים.

### 9.3 שני מצבי אימות

| מצב | מה מאוחסן במכשיר | חוזק | שימוש |
|---|---|---|---|
| **RSA** (ברירת מחדל) | מפתח **ציבורי** בלבד | ✅ גבוה — חילוץ מהמכשיר לא מאפשר זיוף | תקן |
| **HMAC** | סוד מכשיר (DPAPI‑Machine) | ⚠️ בינוני — חילוץ הסוד מאפשר יצירת קודים | Fallback אופליין מלא |

> **הערת אבטחה מחייבת:** מצב HMAC מאחסן במכשיר סוד שמאפשר, במקרה של חילוץ בהרשאות SYSTEM,
> ליצור קודי הסרה עצמאית. לכן ברירת המחדל היא **RSA**, ו‑HMAC מיועד רק לתחנות ללא קישוריות.

### 9.4 הגבלת קצב ועמידות לשינוי שעון

מצב הניסיונות נשמר ב‑`%ProgramData%\SafeMe\state\uninstall.dat`:

* מוצפן DPAPI‑Machine + MAC על התוכן.
* ACL: SYSTEM (Full), Administrators (Read).
* נשמר גם `lastSeenUtc` **מונוטוני** — אם שעון המערכת מוסט אחורה, הנעילה **אינה** מתקצרת;
  נלקח `max(lockoutUntil, lastSeen + remaining)`.
* מחיקת הקובץ ← נחשבת `tamperEvent` **ומאתחלת את המצב לנעול** (Fail‑Secure), לא לפתוח.

---

## 10. רישוי, פעימה וניטור

| נושא | החלטה |
|---|---|
| קשירת רישיון | ל‑HWID; השרת מחזיק `maxDevices` לכל רישיון |
| תדירות פעימה | 180 שניות ± jitter של 15 שניות (מניעת עומס מתואם) |
| כשל תקשורת | Backoff אקספוננציאלי 30ש' ← 5 דק' (מקס), תור אירועים מקומי עד 500 רשומות |
| מצב חסד | `graceMinutes` (ברירת מחדל 720) — לאחריו הפעולה נקבעת במדיניות |
| חידוש טוקן | JWT ל‑7 ימים, חידוש אוטומטי בפעימה |
| ניטור צד שרת | Dead Man's Switch (§4.5) |

---

## 11. אחסון מקומי

```
%ProgramData%\SafeMe\
├── config\agent.json          # קונפיג בסיסי (URL שרת, מזהי התקנה)
├── state\device.dat           # DPAPI-Machine: DeviceToken, DeviceSecret
├── state\policy.json          # חבילת המדיניות האחרונה + חתימה
├── state\uninstall.dat        # מצב Challenge/Response ו-Rate limit
├── queue\events.ndjson        # תור אירועים שלא נשלחו
└── logs\safeme-YYYYMMDD.log   # לוגים מתגלגלים, 14 ימים
```

ACL על כל התיקייה: `SYSTEM:F`, `Administrators:F`, `Users:R` (על `logs` בלבד).

---

## 12. מודל איומים (תמצית)

| # | איום | הגנה |
|---|---|---|
| T1 | עצירת השירות מ‑`services.msc` | ACL על השירות + SCM Recovery + TrayApp Watchdog + Scheduled Task |
| T2 | מחיקת קבצי התוכנה | ACL + שחזור על ידי Guardian + דיווח Tamper |
| T3 | מחיקת חוקי WFP ידנית | Provider ייעודי, אימות תקופתי (כל 30ש') ובנייה מחדש |
| T4 | Boot ל‑Safe Mode | רישום השירות ב‑`SafeBoot\Minimal` וב‑`Network` |
| T5 | שינוי שעון מערכת אחורה | זמן מונוטוני + חלון זמן דו‑כיווני + הצלבת `serverUtc` |
| T6 | Replay של קוד הסרה ישן | Nonce חד‑פעמי + חלון 30 דק' + סימון "נוצל" |
| T7 | זיוף שרת (DNS spoof) | Certificate Pinning ל‑SPKI + חתימת RSA על המדיניות |
| T8 | VPN/Proxy לעקיפת הסינון | חוקי WFP חוסמים יעדים לא מאושרים; זיהוי מתאמי TAP/WinTun ידועים |
| T9 | הרצה כ‑VM או שכפול | HWID מבוסס SMBIOS + זיהוי היפרוויזור מדווח לשרת |
| T10 | הזרקת קוד ל‑TrayApp | ה‑TrayApp הוא תצוגה בלבד; אין לו סמכות אכיפה |

---

## 13. מצבי כשל וטיפול

| כשל | תגובה |
|---|---|
| WFP לא זמין / BFE מושבת | ניסיון הפעלת `BFE`, דיווח `tamperEvent`, מעבר ל‑`Warn` + התראה |
| השרת לא זמין | תור מקומי + Backoff; מדיניות אחרונה תקפה עד `ttl + grace` |
| מדיניות עם חתימה שגויה | דחייה מוחלטת, שמירה על המדיניות הקודמת, דיווח אירוע |
| שעון לא מסונכרן | הסתמכות על `serverUtc` מהפעימה האחרונה כעוגן |
| אין סשן משתמש פעיל | Watchdog מדלג; האכיפה ממשיכה ברמת השירות |

---

## 14. תוכנית בדיקות

1. **יחידה (xUnit):** Base32, CRC16, קידוד/פענוח אתגר, אימות HMAC/RSA, Rate‑limit, חישוב ציון.
2. **אינטגרציה:** `WfpEngine` מול BFE אמיתי (VM), אימות שהחוקים נוצרו ונמחקו.
3. **חוסן:** `taskkill /f` על השירות ועל ה‑TrayApp ← מדידת זמן התאוששות (יעד < 10ש').
4. **חירום:** Lockout מלא ← אימות שהתקשורת לשרת שורדת ושהשחרור עובד.
5. **הסרה:** 3 קודים שגויים ← נעילה, ניסיון Replay, שינוי שעון.

---

## 15. שלבי פיתוח

| שלב | תכולה | סטטוס |
|---|---|---|
| M1 | Core + Challenge/Response + בדיקות | ✅ מומש |
| M2 | Service + IPC + Audit Engine | ✅ מומש |
| M3 | WFP Engine + Enforcement | ✅ מומש |
| M4 | TrayApp + Uninstaller (עברית RTL) | ✅ מומש |
| M5 | Watchdog כפול + התקנה | ✅ מומש |
| M6 | שרת ניהול | ⏳ מחוץ להיקף |
| M7 | חתימת קוד + MSI/WiX | ⏳ מחוץ להיקף |
