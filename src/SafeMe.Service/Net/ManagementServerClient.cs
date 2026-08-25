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
    public string BaseUrl { get; set; } = "https://api.safeme.io";

    /// <summary>שמות המארחים שתמיד מותרים בנעילת חירום.</summary>
    public List<string> AlwaysAllowHosts { get; set; } = new() { "api.safeme.io" };

    /// <summary>טביעות אצבע SPKI לקיבוע תעודה. ריק משבית קיבוע.</summary>
    public List<string> PinnedSpkiSha256 { get; set; } = new();

    public int HeartbeatSeconds { get; set; } = 180;
    public int AuditMinutes { get; set; } = 15;

    /// <summary>אסימון רישום חד-פעמי, נכתב על ידי המתקין.</summary>
    public string? EnrollToken { get; set; }
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
                _log.LogWarning("רישום המכשיר נדחה עם קוד {Status}.", (int)response.StatusCode);
                return null;
            }

            return await response.Content.ReadFromJsonAsync<EnrollResponse>(SafeMeJson.Options, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "רישום המכשיר נכשל.");
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
                _log.LogWarning("אסימון המכשיר נדחה. יידרש רישום מחדש.");

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
}
