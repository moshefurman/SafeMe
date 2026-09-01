using System.Net;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SafeMe.Core;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Core.Security;
using SafeMe.Service.State;

namespace SafeMe.Service.Net;

public sealed class ServerOptions
{
    /*
     * מארח חי, לא שם עתידי.
     *
     * api.safeme.io טרם קיים, והשם שאינו נפתר הפך למוקש: התקנה
     * שנקטעה לפני שהתצורה נכתבה השאירה אותו על הדיסק, וכל משיכת
     * מדיניות נכשלה ב-SocketException. מחשב שאיבד כך את הכתובת
     * אינו יכול גם לקבל את העדכון שיתקן אותה.
     *
     * ברירת מחדל חייבת להיות מקום שבאמת עונה. כשיהיה שם קבוע,
     * הוא ייכנס לכאן ביום שבו הוא יתחיל לענות.
     */
    public string BaseUrl { get; set; } = "https://safeme-1-i3km.onrender.com";

    /// <summary>שמות המארחים שתמיד מותרים בנעילת חירום.</summary>
    public List<string> AlwaysAllowHosts { get; set; } = new() { "safeme-1-i3km.onrender.com" };

    /// <summary>טביעות אצבע SPKI לקיבוע תעודה. ריק משבית קיבוע.</summary>
    public List<string> PinnedSpkiSha256 { get; set; } = new();

    public int HeartbeatSeconds { get; set; } = 180;
    public int AuditMinutes { get; set; } = 15;

    /// <summary>
    /// מה נבחר בהתקנה לגבי אופן ההסרה, ומועבר ברישום.
    ///
    /// נשמר בקובץ התצורה ולא נגזר מכלום, כי הוא נקבע ברגע אחד —
    /// כשההורה עומד מול המחשב — ואין לו מקור אחר.
    /// </summary>
    public string? UninstallPolicy { get; set; }

    /// <summary>אסימון רישום חד-פעמי, נכתב על ידי המתקין.</summary>
    public string? EnrollToken { get; set; }

    /// <summary>
    /// התקנה ללא חשבון.
    ///
    /// המחשב חסום לחלוטין ואינו מדבר עם שום שרת. הדגל נכתב על ידי
    /// המתקין ואינו נגזר מהיעדר אסימון — קובץ תצורה שנפגם והשמיט
    /// אסימון היה מפעיל חסימה מוחלטת בטעות.
    /// </summary>
    public bool Unmanaged { get; set; }

    /// <summary>
    /// המפתח הציבורי לאימות קודי הסרה, מוטבע בהתקנה.
    ///
    /// במסלול הרגיל הוא מגיע מהשרת בתשובת הרישום. בהתקנה ללא
    /// חשבון אין רישום, ולכן הוא חייב להיות כאן — אחרת המחשב
    /// נחסם בלי שום דרך לאמת קוד הסרה, וזו חסימה לצמיתות.
    ///
    /// ציבורי, ולכן הטבעתו אינה חושפת דבר.
    /// </summary>
    public string? UninstallPublicKeyPem { get; set; }
}

/// <summary>
/// לקוח שרת הניהול. אחראי על רישום, משיכת מדיניות, פעימה ודיווח אירועים.
///
/// כל שגיאת רשת מטופלת בשקט ומוחזרת כ-null, כי ניתוק זמני הוא מצב תפעולי
/// רגיל ולא תקלה. ההחלטה מה לעשות בניתוק ממושך מתקבלת בשכבת ה-Workers.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ManagementServerClient : IManagementServerClient
{
    private readonly ILogger<ManagementServerClient> _log;
    private readonly IHttpClientFactory _httpFactory;
    private readonly DeviceStateStore _deviceStore;
    private readonly IHardwareIdProvider _hwid;
    private readonly ServerOptions _options;

    public ManagementServerClient(
        ILogger<ManagementServerClient> log,
        IHttpClientFactory httpFactory,
        DeviceStateStore deviceStore,
        IHardwareIdProvider hwid,
        IOptions<ServerOptions> options)
    {
        _log = log;
        _httpFactory = httpFactory;
        _deviceStore = deviceStore;
        _hwid = hwid;
        _options = options.Value;
    }

    private HttpClient CreateClient()
    {
        var client = _httpFactory.CreateClient("server");
        client.BaseAddress = new Uri(_options.BaseUrl.TrimEnd('/') + "/");

        var device = _deviceStore.Load();

        if (!string.IsNullOrEmpty(device.DeviceToken))
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", device.DeviceToken);

        client.DefaultRequestHeaders.Add("X-SafeMe-Hwid", _hwid.GetHardwareId());

        return client;
    }

    public async Task<EnrollResponse?> EnrollAsync(EnrollRequest request, CancellationToken ct)
    {
        try
        {
            using var client = CreateClient();
            using var response = await client.PostAsJsonAsync("api/v1/enroll", request, SafeMeJson.Options, ct);

            if (!response.IsSuccessStatusCode)
            {
                _log.LogWarning("רישום המחשב נדחה עם קוד {Status}.", (int)response.StatusCode);
                return null;
            }

            return await response.Content.ReadFromJsonAsync<EnrollResponse>(SafeMeJson.Options, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "רישום המחשב נכשל.");
            return null;
        }
    }

    public async Task<PolicyResponse> GetPolicyAsync(string? etag, CancellationToken ct)
    {
        try
        {
            using var client = CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, "api/v1/policy");

            if (!string.IsNullOrEmpty(etag))
                request.Headers.TryAddWithoutValidation("If-None-Match", etag);

            using var response = await client.SendAsync(request, ct);

            if (response.StatusCode == HttpStatusCode.NotModified)
                return new PolicyResponse { NotModified = true, Etag = etag };

            if (!response.IsSuccessStatusCode)
            {
                _log.LogWarning("משיכת מדיניות נכשלה עם קוד {Status}.", (int)response.StatusCode);
                return new PolicyResponse();
            }

            var envelope = await response.Content.ReadFromJsonAsync<SignedEnvelope>(SafeMeJson.Options, ct);

            return new PolicyResponse
            {
                Envelope = envelope,
                Etag = response.Headers.ETag?.ToString()
            };
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "משיכת מדיניות נכשלה.");
            return new PolicyResponse();
        }
    }

    public async Task<HeartbeatResponse?> SendHeartbeatAsync(HeartbeatRequest request, CancellationToken ct)
    {
        try
        {
            using var client = CreateClient();
            using var response = await client.PostAsJsonAsync("api/v1/heartbeat", request, SafeMeJson.Options, ct);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _log.LogWarning("אסימון המחשב נדחה. יידרש רישום מחדש.");

                _deviceStore.Update(state => state.DeviceToken = null);

                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                _log.LogDebug("פעימה נדחתה עם קוד {Status}.", (int)response.StatusCode);
                return null;
            }

            return await response.Content.ReadFromJsonAsync<HeartbeatResponse>(SafeMeJson.Options, ct);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "שליחת פעימה נכשלה.");
            return null;
        }
    }

    public async Task<bool> SendAuditAsync(AuditReport report, CancellationToken ct)
    {
        try
        {
            using var client = CreateClient();
            using var response = await client.PostAsJsonAsync("api/v1/audit", report, SafeMeJson.Options, ct);

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "שליחת דוח ביקורת נכשלה.");
            return false;
        }
    }

    public async Task<bool> SendEventsAsync(IReadOnlyList<TamperEvent> events, CancellationToken ct)
    {
        if (events.Count == 0) return true;

        try
        {
            using var client = CreateClient();
            using var response = await client.PostAsJsonAsync("api/v1/events", events, SafeMeJson.Options, ct);

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "שליחת אירועים נכשלה.");
            return false;
        }
    }

    public async Task<bool> ReportUninstalledAsync(CancellationToken ct)
    {
        try
        {
            using var client = CreateClient();

            using var response = await client.PostAsJsonAsync(
                "api/v1/uninstalled", new { }, SafeMeJson.Options, ct);

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            /*
             * כישלון כאן אינו עוצר את ההסרה.
             *
             * המחשב עשוי להיות מנותק בדיוק בגלל מה שמסירים, וקישור
             * בין "השרת ענה" לבין "אפשר להסיר" היה הופך תקלת רשת
             * למחשב שאי אפשר לנקות. הרשימה בפורטל תתוקן ידנית.
             */
            _log.LogDebug(ex, "דיווח ההסרה לשרת נכשל.");
            return false;
        }
    }

    public async Task<bool> SendLogBundleAsync(byte[] gzip, Guid commandId, CancellationToken ct)
    {
        try
        {
            using var client = CreateClient();
            using var content = new ByteArrayContent(gzip);

            content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

            /*
             * ההקשר בכותרות ולא בגוף.
             *
             * הגוף הוא בתים דחוסים ואין בו מקום לשדות. מזהה הפקודה
             * הוא מה שמחבר את היומן לבקשה שגרמה לו — בלעדיו אי אפשר
             * לענות "מי ביקש את זה ומתי".
             */
            content.Headers.Add("X-SafeMe-Command", commandId.ToString());
            content.Headers.Add(
                "X-SafeMe-Agent",
                System.Diagnostics.FileVersionInfo
                    .GetVersionInfo(System.Reflection.Assembly.GetExecutingAssembly().Location)
                    .FileVersion ?? "0.0.0");
            content.Headers.Add("X-SafeMe-Collected", DateTimeOffset.UtcNow.ToString("O"));

            using var response = await client.PostAsync("api/v1/logs", content, ct);

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "שליחת יומן האבחון נכשלה.");
            return false;
        }
    }
}
