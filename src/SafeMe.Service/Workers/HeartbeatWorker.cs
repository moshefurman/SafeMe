using System.Reflection;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Service.Audit;
using SafeMe.Service.Net;
using SafeMe.Service.State;

namespace SafeMe.Service.Workers;

/// <summary>
/// אחראי על הקשר עם השרת: רישום ראשוני, רענון מדיניות, פעימה קבועה
/// וביצוע פקודות מרחוק.
///
/// כשל תקשורת אינו נחשב תקלה. הפעימה עוברת ל-Backoff, ובמקביל נמדד
/// משך הניתוק מול חלון החסד שבמדיניות.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HeartbeatWorker : BackgroundService
{
    private static readonly string AgentVersion =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    private readonly ILogger<HeartbeatWorker> _log;
    private readonly IManagementServerClient _server;
    private readonly DeviceStateStore _deviceStore;
    private readonly PolicyStore _policyStore;
    private readonly IAgentStateProvider _state;
    private readonly IHardwareIdProvider _hwid;
    private readonly EnforcementCoordinator _enforcement;
    private readonly UpdateWorker _updates;
    private readonly NetworkIdentityAuditor _network;
    private readonly EventQueue _events;
    private readonly AuditWorker _auditWorker;
    private readonly UninstallCoordinator _uninstall;
    private readonly ServerOptions _options;

    private TimeSpan _backoff = TimeSpan.Zero;

    public HeartbeatWorker(
        ILogger<HeartbeatWorker> log,
        IManagementServerClient server,
        DeviceStateStore deviceStore,
        PolicyStore policyStore,
        IAgentStateProvider state,
        IHardwareIdProvider hwid,
        EnforcementCoordinator enforcement,
        UpdateWorker updates,
        NetworkIdentityAuditor network,
        EventQueue events,
        AuditWorker auditWorker,
        UninstallCoordinator uninstall,
        IOptions<ServerOptions> options)
    {
        _log = log;
        _server = server;
        _deviceStore = deviceStore;
        _policyStore = policyStore;
        _state = state;
        _hwid = hwid;
        _enforcement = enforcement;
        _updates = updates;
        _network = network;
        _events = events;
        _auditWorker = auditWorker;
        _uninstall = uninstall;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        /*
         * התקנה ללא חשבון אינה מדברת עם שרת.
         *
         * לא רק שאין לה למי — היא גם חוסמת את עצמה מלנסות, ולכן
         * כל פנייה כאן הייתה מסתיימת בפסק זמן. יציאה מוקדמת עדיפה
         * על לולאה שנכשלת בשקט כל שלוש דקות ומציפה את היומן.
         *
         * ההסרה במצב הזה אינה עוברת דרך השרת אלא דרך קוד אתגר
         * מקומי, ולכן אין כאן פונקציונליות שאובדת.
         */
        if (_options.Unmanaged)
        {
            _log.LogInformation("התקנה ללא חשבון. אין תקשורת עם שרת.");

            await _enforcement.ReevaluateAsync(stoppingToken);

            return;
        }

        await EnsureEnrolledAsync(stoppingToken);
        await RefreshPolicyAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!_uninstall.Disarmed)
                await SendHeartbeatAsync(stoppingToken);

            var jitter = TimeSpan.FromSeconds(Random.Shared.Next(-15, 15));
            var delay = TimeSpan.FromSeconds(_options.HeartbeatSeconds) + jitter + _backoff;

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        await ReportGracefulShutdownAsync();
    }

    /// <summary>רושם את המחשב אם עדיין אין אסימון תקף.</summary>
    private async Task EnsureEnrolledAsync(CancellationToken ct)
    {
        var device = _deviceStore.Load();

        if (!string.IsNullOrEmpty(device.DeviceToken)) return;

        var hwid = _hwid.GetHardwareId();

        var request = new EnrollRequest
        {
            Hwid = hwid,
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.VersionString,
            AgentVersion = AgentVersion,
            EnrollToken = _options.EnrollToken,
            InstallId = device.InstallId
        };

        var response = await _server.EnrollAsync(request, ct);

        if (response is null)
        {
            _log.LogWarning("רישום המחשב לא הושלם. יבוצע ניסיון חוזר בפעימה הבאה.");
            return;
        }

        _deviceStore.Update(state =>
        {
            state.DeviceId = response.DeviceId;
            state.DeviceToken = response.DeviceToken;
            state.PolicyEtag = response.PolicyEtag;
            state.UninstallKeyMode = response.UninstallKeyMode;
            state.ServerPublicKeyPem = response.ServerPublicKeyPem;

            state.LooseningPublicKeyPem = response.LooseningPublicKeyPem;
            state.UninstallPublicKeyPem = response.UninstallPublicKeyPem;
            state.UpdatePublicKeyPem = response.UpdatePublicKeyPem;
            state.DeviceSecretBase64 = response.DeviceSecret;
            state.InstallProfile = response.InstallProfile;
            state.EnforcementMode = response.EnforcementMode;
            state.LicenseExpiresUtc = response.LicenseExpiresUtc;
            state.LicenseValid = true;
        });

        // רצפת המדיניות היא מה שהופך את המחגר לאמיתי. בלעדיה המחשב
        // יקבל כל מדיניות חתומה, כולל כזו שמכבה את האכיפה.
        if (response.PolicyFloor is not null)
        {
            if (!_policyStore.SetFloorFromEnvelope(response.PolicyFloor, response.ServerPublicKeyPem, hwid))
            {
                _events.Enqueue(new TamperEvent
                {
                    Kind = TamperKind.PolicySignatureInvalid,
                    Detail = "רצפת המדיניות שהתקבלה ברישום נדחתה."
                });
            }
        }
        else
        {
            _log.LogWarning("הרישום לא כלל רצפת מדיניות. נשמרת רצפת ברירת המחדל המחמירה.");
        }

        _log.LogInformation(
            "המחשב נרשם בהצלחה. פרופיל {Profile}, מצב {Mode}, קוד הסרה {KeyMode}.",
            response.InstallProfile ?? "לא צוין", response.EnforcementMode, response.UninstallKeyMode);
    }

    private async Task RefreshPolicyAsync(CancellationToken ct)
    {
        var device = _deviceStore.Load();
        var response = await _server.GetPolicyAsync(device.PolicyEtag, ct);

        if (response.NotModified || response.Envelope is null) return;

        var outcome = _policyStore.AcceptEnvelope(response.Envelope, device.ServerPublicKeyPem);

        if (outcome.Accepted)
        {
            _deviceStore.Update(state => state.PolicyEtag = response.Etag);
            await _enforcement.ReevaluateAsync(ct);

            return;
        }

        // דחיית מדיניות היא תמיד אירוע שדורש דיווח. מדיניות שמנסה להקל
        // מתחת לרצפה חשודה במיוחד: היא עלולה להעיד על שרת פרוץ.
        _events.Enqueue(new TamperEvent
        {
            Kind = TamperKind.PolicySignatureInvalid,
            Detail = outcome.LooseningReasons.Count > 0
                ? $"מדיניות נדחתה כמקלה מתחת לרצפה: {string.Join(" | ", outcome.LooseningReasons)}"
                : $"מדיניות נדחתה ({outcome.Status}): {outcome.Message}"
        });
    }

    private async Task SendHeartbeatAsync(CancellationToken ct)
    {
        var snapshot = _state.Current;
        var device = _deviceStore.Load();
        var pending = _events.DrainAll();

        var request = new HeartbeatRequest
        {
            Hwid = _hwid.GetHardwareId(),
            AgentVersion = AgentVersion,
            PolicyVersion = _policyStore.Current.Version,
            Sequence = device.HeartbeatSequence + 1,
            Status = snapshot.Status,
            Score = snapshot.Score,
            Enforcement = _policyStore.Current.Enforcement.Mode,
            ActiveAdapters = _network.GetActiveAdapters(),
            PublicIp = snapshot.PublicIp,
            DetectedProvider = snapshot.ProviderId,
            FailedProbes = snapshot.FailedProbes.Select(p => p.Id).ToList(),
            TamperEvents = pending,
            WfpFilterCount = snapshot.WfpFilterCount,
            UptimeSec = snapshot.UptimeSeconds,
            LockoutActive = snapshot.LockoutActive
        };

        var response = await _server.SendHeartbeatAsync(request, ct);

        if (response is null)
        {
            // האירועים חוזרים לתור כדי שלא ילכו לאיבוד בניתוק
            _events.Requeue(pending);
            ApplyBackoff();

            return;
        }

        _events.ClearDisk();
        ResetBackoff();


        _deviceStore.Update(state =>
        {
            state.HeartbeatSequence = request.Sequence;
            state.LastServerContactUtc = DateTimeOffset.UtcNow;
            state.LastServerUtc = response.ServerUtc;
            state.LicenseValid = response.LicenseValid;
            state.LicenseExpiresUtc = response.LicenseExpiresUtc ?? state.LicenseExpiresUtc;
        });

        _state.Update(s =>
        {
            s.LastHeartbeatUtc = DateTimeOffset.UtcNow;
            s.LastServerContactUtc = DateTimeOffset.UtcNow;
            s.LicenseValid = response.LicenseValid;
            s.LicenseExpiresUtc = response.LicenseExpiresUtc;
        });

        // סטיית שעון גדולה מול השרת עלולה להצביע על ניסיון לעקוף חלונות זמן
        var drift = (DateTimeOffset.UtcNow - response.ServerUtc).Duration();

        if (drift > TimeSpan.FromMinutes(10))
        {
            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.ClockRolledBack,
                Detail = $"סטיית שעון של {drift.TotalMinutes:F0} דקות מול השרת."
            });
        }

        // ההכרעה על הרשת מוחלת לפני המדיניות והפקודות.
        //
        // רשת שאינה מאושרת נחסמת מיד, ולא ממתינה לרענון מדיניות
        // שעשוי להיכשל. זו הנקודה היחידה שבה ההכרעה נכנסת לתוקף.
        /*
         * זהות הרשת הנוכחית, כפי שהסוכן רואה אותה.
         *
         * היא הצמד שההכרעה נקשרת אליו. שם הרשת לבדו אינו מספיק —
         * שתי רשתות יכולות לשאת אותו שם — ולכן גם השער.
         */
        var current = _network.GetActiveAdapters()
            .Select(a => $"{a.Ssid}|{a.Gateway}")
            .FirstOrDefault(id => id != "|");

        /*
         * הכרעה שנאמרה על רשת אחרת מבוטלת לפני שמחילים כל דבר.
         *
         * תשובת פעימה שאינה כוללת הכרעה השאירה את הקודמת בתוקף,
         * והמחשב הציג "ממתינה לאישור" על רשת שכבר התחלף ממנה —
         * ואז חסם, בלי שום דרך לצאת מזה.
         */
        await _enforcement.ForgetVerdictIfNetworkChangedAsync(current, ct);

        if (response.Network is { } verdict)
        {
            await _enforcement.SetNetworkVerdictAsync(verdict.Action, verdict.Reason, current, ct);

            if (verdict.IsNew)
            {
                _log.LogInformation(
                    "רשת חדשה זוהתה: {Ssid}. {Reason}",
                    verdict.Ssid ?? "ללא שם", verdict.Reason);
            }
        }

        if (!string.IsNullOrEmpty(response.PolicyEtag) && response.PolicyEtag != device.PolicyEtag)
            await RefreshPolicyAsync(ct);

        foreach (var command in response.Commands)
            await ExecuteCommandAsync(command, ct);

        /*
         * העדכון אחרון, ובכוונה.
         *
         * כשהוא מצליח, המתקין עוצר את השירות הזה תוך שניות. כל מה
         * שקודם לו — הכרעת הרשת, המדיניות, הפקודות — צריך להספיק
         * להיכנס לתוקף קודם, אחרת פקודת נעילה שהגיעה באותה פעימה
         * הייתה הולכת לאיבוד.
         */
        if (await _updates.TryApplyAsync(response.Update, DateTimeOffset.UtcNow, ct))
        {
            _log.LogWarning("עדכון הוחל. השירות ייעצר על ידי המתקין.");
        }
    }

    private async Task ExecuteCommandAsync(RemoteCommand command, CancellationToken ct)
    {
        _log.LogInformation("מבצע פקודה מרחוק: {Type}", command.Type);

        try
        {
            switch (command.Type)
            {
                case "RefreshPolicy":
                    _deviceStore.Update(state => state.PolicyEtag = null);
                    await RefreshPolicyAsync(ct);
                    break;

                case "Lockout":
                    var minutes = command.Args.TryGetValue("minutes", out var raw) &&
                                  int.TryParse(raw, out var parsed)
                        ? parsed
                        : 30;

                    command.Args.TryGetValue("reason", out var reason);
                    await _enforcement.StartRemoteLockoutAsync(minutes, reason, ct);
                    break;

                case "ReleaseLockout":
                    await _enforcement.ReleaseRemoteLockoutAsync(ct);
                    break;

                case "RunAudit":
                    await _auditWorker.RunOnceAsync(ct);
                    break;

                default:
                    _log.LogWarning("פקודה לא מוכרת התקבלה ודולגה: {Type}", command.Type);
                    break;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "ביצוע פקודה {Type} נכשל.", command.Type);
        }
    }

    /// <summary>מכפיל את ההשהיה עד לתקרה, כדי לא להציף שרת שנמצא בתקלה.</summary>
    private void ApplyBackoff()
    {
        var next = _backoff == TimeSpan.Zero ? TimeSpan.FromSeconds(30) : _backoff * 2;

        _backoff = next > TimeSpan.FromMinutes(5) ? TimeSpan.FromMinutes(5) : next;

        _log.LogDebug("אין קשר לשרת. ההשהיה הנוספת עודכנה ל-{Backoff}.", _backoff);
    }

    private void ResetBackoff() => _backoff = TimeSpan.Zero;

    /// <summary>
    /// מדווח כיבוי מסודר, כדי שה-Dead Man's Switch בצד השרת לא ידווח
    /// על ניתוק כשמדובר בכיבוי רגיל של המחשב.
    /// </summary>
    private async Task ReportGracefulShutdownAsync()
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            await _server.SendEventsAsync(
            [
                new TamperEvent
                {
                    Kind = TamperKind.ServiceStopAttempt,
                    Detail = "כיבוי מסודר של השירות."
                }
            ], cts.Token);
        }
        catch (Exception)
        {
            // כיבוי מסודר לא ייכשל בגלל דיווח שלא נשלח
        }
    }
}
