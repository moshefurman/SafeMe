using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;
using SafeMe.Service.Audit;
using SafeMe.Service.Net;
using SafeMe.Service.State;
using SafeMe.Service.Wfp;

namespace SafeMe.Service.Workers;

/// <summary>
/// מחליט איזו תוכנית אכיפה צריכה להיות פעילה ומחיל אותה.
///
/// כאן מתנקזות כל הסיבות לחסימה: סטטוס אדום, לוח זמנים מהמדיניות,
/// נעילה יזומה מהשרת, ורשימת רשתות מותרות. הפרדת ההחלטה מהמימוש
/// מאפשרת לבדוק את ההיגיון בלי לגעת ב-WFP.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EnforcementCoordinator
{
    private readonly ILogger<EnforcementCoordinator> _log;
    private readonly IEnforcementEngine _engine;
    private readonly IAgentStateProvider _state;
    private readonly PolicyStore _policy;
    private readonly NetworkIdentityAuditor _network;
    private readonly ServerOptions _serverOptions;
    private readonly SemaphoreSlim _sync = new(1, 1);

    private DateTimeOffset? _remoteLockoutUntil;
    private string? _remoteLockoutReason;

    public EnforcementCoordinator(
        ILogger<EnforcementCoordinator> log,
        IEnforcementEngine engine,
        IAgentStateProvider state,
        PolicyStore policy,
        NetworkIdentityAuditor network,
        IOptions<ServerOptions> serverOptions)
    {
        _log = log;
        _engine = engine;
        _state = state;
        _policy = policy;
        _network = network;
        _serverOptions = serverOptions.Value;
    }

    /// <summary>תקרת משך לנעילה יזומה יחידה. ראה MaxLockout למטה.</summary>
    public const int MaxLockoutMinutes = 24 * 60;

    /// <summary>
    /// מפעיל נעילה יזומה מהשרת.
    ///
    /// כלל מחייב: לכל נעילה יש זמן סיום, והוא נספר על ידי המכשיר עצמו.
    /// אין נעילה אינסופית ואין נעילה שתלויה בכך שהשרת ישלח "שחרר" —
    /// אחרת נפילת שרת הייתה משאירה מכשירים חסומים בלי דרך חזרה.
    /// מי שרוצה חסימה מתמשכת מחדש אותה בכל פעימה.
    /// </summary>
    public async Task StartRemoteLockoutAsync(int minutes, string? reason, CancellationToken ct)
    {
        if (minutes <= 0)
        {
            _log.LogWarning("פקודת נעילה ללא משך תקף ({Minutes}) נדחתה.", minutes);
            return;
        }

        var capped = Math.Min(minutes, MaxLockoutMinutes);

        if (capped != minutes)
        {
            _log.LogWarning(
                "משך הנעילה קוצר מ-{Requested} ל-{Capped} דקות (תקרה).", minutes, capped);
        }

        _remoteLockoutUntil = DateTimeOffset.UtcNow.AddMinutes(capped);
        _remoteLockoutReason = reason ?? "נעילה יזומה מהמערכת";

        _log.LogWarning(
            "התקבלה פקודת נעילה ל-{Minutes} דקות, עד {Until:HH:mm}. סיבה: {Reason}",
            capped, _remoteLockoutUntil.Value.ToLocalTime(), _remoteLockoutReason);

        await ReevaluateAsync(ct);
    }

    public async Task ReleaseRemoteLockoutAsync(CancellationToken ct)
    {
        _remoteLockoutUntil = null;
        _remoteLockoutReason = null;

        _log.LogInformation("נעילה יזומה שוחררה.");

        await ReevaluateAsync(ct);
    }

    /// <summary>
    /// בונה מחדש את תוכנית האכיפה מהמצב הנוכחי ומחיל אותה.
    /// נקרא אחרי כל ביקורת, אחרי כל פקודה מהשרת, ובבדיקת שלמות תקופתית.
    /// </summary>
    public async Task ReevaluateAsync(CancellationToken ct)
    {
        await _sync.WaitAsync(ct);

        try
        {
            var policy = _policy.Current;
            var snapshot = _state.Current;

            var (shouldBlock, reason) = DecideBlock(policy, snapshot);

            if (!shouldBlock)
            {
                if (snapshot.LockoutActive)
                    _log.LogInformation("תנאי החסימה הוסרו. האכיפה משוחררת.");

                _engine.Apply(EnforcementPlan.Disabled);

                _state.Update(s =>
                {
                    s.LockoutActive = false;
                    s.LockoutUntil = null;
                    s.LockoutReason = null;
                    s.WfpFilterCount = _engine.ActiveFilterCount;
                });

                return;
            }

            var plan = await BuildLockoutPlanAsync(policy, reason, ct);

            _engine.Apply(plan);

            _state.Update(s =>
            {
                s.LockoutActive = true;
                s.LockoutUntil = _remoteLockoutUntil;
                s.LockoutReason = reason;
                s.Status = SecurityStatus.Blocked;
                s.Headline = $"נעילה פעילה: {reason}";
                s.WfpFilterCount = _engine.ActiveFilterCount;
            });
        }
        finally
        {
            _sync.Release();
        }
    }

    /// <summary>קובע אם יש לחסום, ומה הסיבה. הסיבות נבדקות לפי סדר עדיפות.</summary>
    private (bool Block, string Reason) DecideBlock(PolicyBundle policy, StatusSnapshot snapshot)
    {
        // 1. נעילה יזומה מהשרת גוברת על הכול
        if (_remoteLockoutUntil is { } until)
        {
            if (DateTimeOffset.UtcNow < until)
                return (true, _remoteLockoutReason ?? "נעילה יזומה");

            _remoteLockoutUntil = null;
            _remoteLockoutReason = null;
        }

        // 2. חלון זמן מתוזמן מהמדיניות
        var localNow = DateTime.Now;
        var activeSchedule = policy.Enforcement.Schedules.FirstOrDefault(s => s.IsActiveAt(localNow));

        if (activeSchedule is not null)
            return (true, $"חסימה מתוזמנת ({activeSchedule.From}-{activeSchedule.To})");

        // 3. במצבי ניטור והתראה לא חוסמים בכלל
        if (policy.Enforcement.Mode != EnforcementMode.Enforce)
            return (false, "");

        // 4. סטטוס אדום עם פעולת נעילה מוגדרת
        if (snapshot.Status == SecurityStatus.Unfiltered &&
            policy.Enforcement.OnRedAction == RedAction.Lockout)
            return (true, "החיבור אינו מסונן");

        // 5. רשת אלחוטית שאינה ברשימה המותרת
        var allowedSsids = policy.Enforcement.AllowedNetworks.WifiSsids;

        if (allowedSsids.Count > 0 && snapshot.WifiSsid is { } ssid &&
            !allowedSsids.Contains(ssid, StringComparer.OrdinalIgnoreCase))
            return (true, $"הרשת האלחוטית {ssid} אינה מאושרת");

        return (false, "");
    }

    /// <summary>
    /// בונה תוכנית נעילה. הכתובות של שרת הניהול מיושבות מראש, כדי שהמכשיר
    /// יישאר בקשר עם השרת גם כשה-DNS חסום.
    /// </summary>
    private async Task<EnforcementPlan> BuildLockoutPlanAsync(PolicyBundle policy, string reason, CancellationToken ct)
    {
        var allow = policy.Enforcement.AlwaysAllow;

        var hosts = allow.Hosts
            .Concat(_serverOptions.AlwaysAllowHosts)
            .Concat([new Uri(_serverOptions.BaseUrl).Host])
            .Distinct(StringComparer.OrdinalIgnoreCase);

        var serverIps = await WfpEnforcementEngine.ResolveServerIpsAsync(hosts, _log, ct);
        serverIps.AddRange(allow.Ips);

        return new EnforcementPlan
        {
            BlockAllOutbound = true,
            ServerIps = serverIps.Distinct().ToList(),
            AllowedRemoteCidrs = policy.Enforcement.AllowedNetworks.Cidrs.ToList(),
            AllowedPorts = allow.Ports.ToList(),
            AllowDns = allow.AllowDns,
            AllowDhcp = allow.AllowDhcp,
            AllowLoopback = allow.AllowLoopback,
            AllowedAppPaths = [Environment.ProcessPath ?? ""],
            Reason = reason
        };
    }

    /// <summary>מרענן את פרטי הרשת בתמונת המצב.</summary>
    public void RefreshNetworkInfo()
    {
        var adapters = _network.GetActiveAdapters();
        var primary = adapters.FirstOrDefault();

        _state.Update(s =>
        {
            s.ActiveAdapter = primary?.Name;
            s.WifiSsid = adapters.FirstOrDefault(a => a.Ssid is not null)?.Ssid;
        });
    }
}
