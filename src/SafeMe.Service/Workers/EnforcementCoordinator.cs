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
    private readonly TunnelLocator _tunnels;
    private readonly DeviceStateStore _deviceStore;
    private readonly UninstallCoordinator _uninstall;
    private readonly ServerOptions _serverOptions;
    private readonly SemaphoreSlim _sync = new(1, 1);

    /// <summary>
    /// כמה ביקורות רצופות שאומרות "אינו מסונן" נדרשות לפני חסימה.
    ///
    /// שתיים, לא אחת. הן מרוחקות בפרק זמן של ביקורת, ולכן שתיהן
    /// יחד שוללות תקלה רגעית — ועדיין חוסמות תוך דקות ספורות.
    /// </summary>
    private const int UnfilteredBeforeLockout = 2;

    private int _consecutiveUnfiltered;

    private DateTimeOffset? _remoteLockoutUntil;
    private string? _remoteLockoutReason;

    public EnforcementCoordinator(
        ILogger<EnforcementCoordinator> log,
        IEnforcementEngine engine,
        IAgentStateProvider state,
        PolicyStore policy,
        NetworkIdentityAuditor network,
        TunnelLocator tunnels,
        DeviceStateStore deviceStore,
        UninstallCoordinator uninstall,
        IOptions<ServerOptions> serverOptions)
    {
        _log = log;
        _engine = engine;
        _state = state;
        _policy = policy;
        _network = network;
        _tunnels = tunnels;
        _deviceStore = deviceStore;
        _uninstall = uninstall;
        _serverOptions = serverOptions.Value;
    }

    /// <summary>תקרת משך לנעילה יזומה יחידה. ראה MaxLockout למטה.</summary>
    public const int MaxLockoutMinutes = 24 * 60;

    /// <summary>הכרעת השרת על הרשת הנוכחית. נשמרת עד שתשתנה.</summary>
    private bool _networkBlocked;

    /// <summary>
    /// הרשת שההכרעה נאמרה עליה.
    ///
    /// בלי זה, הכרעה על רשת אחת המשיכה לחול על כל רשת שאחריה: תשובת
    /// פעימה שאינה כוללת הכרעה השאירה את הקודמת בתוקף, והמחשב הציג
    /// "ממתינה לאישור" על רשת שכבר התחלף ממנה.
    ///
    /// החלטה על רשת אחת אינה אומרת דבר על רשת אחרת.
    /// </summary>
    private string? _verdictFor;
    private string? _networkBlockReason;

    /// <summary>
    /// מפעיל נעילה יזומה מהשרת.
    ///
    /// כלל מחייב: לכל נעילה יש זמן סיום, והוא נספר על ידי המחשב עצמו.
    /// אין נעילה אינסופית ואין נעילה שתלויה בכך שהשרת ישלח "שחרר" —
    /// אחרת נפילת שרת הייתה משאירה מחשבים חסומים בלי דרך חזרה.
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

    /// <summary>
    /// קובע את ההכרעה על הרשת הנוכחית, כפי שהתקבלה מהשרת.
    ///
    /// ההכרעה נשמרת ואינה פגה מעצמה. מחשב שמנותק מהשרת ממשיך לאכוף
    /// את מה שידע לאחרונה — אותו עיקרון שחל על כל שאר האכיפה. ניתוק
    /// אינו מרפה, אחרת די היה לחסום את השרת ולהמתין.
    /// </summary>
    public async Task SetNetworkVerdictAsync(
        string? action, string? reason, string? forNetwork, CancellationToken ct)
    {
        // ההכרעה מגיעה כמחרוזת מהשרת. ערך לא מוכר נחשב כחסימה, כי
        // ההנחה הבטוחה כשלא מבינים היא לא להתיר.
        var blocked = action is not null && !string.Equals(action, "allow", StringComparison.OrdinalIgnoreCase);

        _verdictFor = forNetwork;

        if (blocked == _networkBlocked && reason == _networkBlockReason) return;

        _networkBlocked = blocked;
        _networkBlockReason = blocked ? (reason ?? "הרשת אינה מאושרת.") : null;

        if (blocked)
            _log.LogWarning("הרשת הנוכחית נחסמה: {Reason}", _networkBlockReason);
        else
            _log.LogInformation("הרשת הנוכחית אושרה.");

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

            /*
             * מצב default-deny הופך את היחס בין החסימה לשחרור.
             *
             * בלעדיו יש שני מצבים: אכיפה כשמשהו רע קרה, וכלום כשלא.
             * איתו יש תמיד תוכנית — מה שמשתנה הוא כמה היא מתירה.
             * לכן אין כאן מסלול Disabled, וגם "הכול תקין" מיתרגם
             * לחוקים פעילים ולא להיעדרם.
             */
            var egress = policy.Enforcement.Egress;

            // ההתקנה ללא חשבון אינה תלויה במדיניות: אין שרת שישלח
            // אותה, ולכן egress.Enabled יהיה תמיד שקר.
            if (egress.Enabled || _serverOptions.Unmanaged)
            {
                var egressPlan = await BuildEgressPlanAsync(
                    policy, egress, shouldBlock ? reason : null, ct);

                _engine.Apply(egressPlan);

                var locked = egressPlan.Posture is EgressPosture.LockedDown or EgressPosture.Sealed;

                _state.Update(s =>
                {
                    s.LockoutActive = locked;
                    s.LockoutUntil = locked ? _remoteLockoutUntil : null;
                    s.LockoutReason = locked ? egressPlan.Reason : null;
                    s.EgressPosture = egressPlan.Posture.ToString();
                    s.WfpFilterCount = _engine.ActiveFilterCount;

                    if (locked)
                    {
                        s.Status = SecurityStatus.Blocked;
                        s.Headline = egressPlan.Reason;
                    }
                });

                return;
            }

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
                    s.EgressPosture = EgressPosture.Off.ToString();
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


    /// <summary>
    /// מבטל הכרעה שנאמרה על רשת אחרת.
    ///
    /// נקרא בכל פעימה עם זהות הרשת הנוכחית. כשהיא שונה מזו שההכרעה
    /// נאמרה עליה, ההכרעה אינה תקפה עוד — והמחשב אינו רשאי להמשיך
    /// לחסום, או להציג "ממתינה לאישור", על סמך רשת שהוא כבר לא
    /// מחובר אליה.
    ///
    /// הכיוון הבטוח כאן הוא דווקא לשחרר: השרת יכריע על הרשת החדשה
    /// בפעימה הבאה, ועד אז חסימה על סמך החלטה שאינה נוגעת אליה היא
    /// שגיאה שאין ממנה מוצא — בדיוק כפי שקרה בשטח.
    /// </summary>
    public async Task ForgetVerdictIfNetworkChangedAsync(string? currentNetwork, CancellationToken ct)
    {
        if (_verdictFor is null || currentNetwork is null) return;
        if (string.Equals(_verdictFor, currentNetwork, StringComparison.OrdinalIgnoreCase)) return;

        _log.LogInformation(
            "הרשת התחלפה. ההכרעה הקודמת בוטלה עד שתתקבל הכרעה על הרשת הנוכחית.");

        _verdictFor = null;

        await SetNetworkVerdictAsync("allow", null, currentNetwork, ct);
    }

    /// <summary>קובע אם יש לחסום, ומה הסיבה. הסיבות נבדקות לפי סדר עדיפות.</summary>
    private (bool Block, string Reason) DecideBlock(PolicyBundle policy, StatusSnapshot snapshot)
    {
        /*
         * 0. מחשב שמזמן לא שמע מהשרת משחרר.
         *
         * לפני כל השאר, כולל נעילה יזומה — ובכוונה. נעילה שנשלחה
         * לפני חודשיים ומעולם לא בוטלה היא בדיוק המצב שהמנגנון
         * הזה נועד לפתוח.
         *
         * נבנה כשנסגרה ההסרה הכפויה: מאותה נקודה קוד הסרה נחתם
         * ב-KMS ואין דרך אחרת, ומפתח שיאבד היה נועל את כל הצי
         * לצמיתות. זו הדרך היחידה שאינה תלויה בשמירת סוד.
         *
         * ומשחרר ולא חוסם. מחשב שאיבד קשר לצמיתות אינו מחשב
         * שצריך להיחסם — הוא מחשב שאיש כבר לא מנהל.
         */
        var installedUtc = _deviceStore.Load().InstalledUtc;
        var maxOffline = policy.Enforcement.MaxOfflineDays;

        if (OfflineExpiry.Evaluate(
                snapshot.LastServerContactUtc,
                installedUtc,
                DateTimeOffset.UtcNow,
                maxOffline) == OfflineState.Expired)
        {
            /*
             * ופותח גם את ההסרה.
             *
             * שחרור האכיפה לבדו היה משאיר מחשב עם תוכנה שאי אפשר
             * להסיר — בדיוק המלכודת שנפתחה כשההסרה הכפויה נסגרה.
             */
            var daysOffline = maxOffline - OfflineExpiry.DaysLeft(
                snapshot.LastServerContactUtc, installedUtc, DateTimeOffset.UtcNow, maxOffline);

            _uninstall.ApproveBecauseOffline(daysOffline);

            return (false, "המחשב לא שמע מהשרת זמן רב. האכיפה שוחררה וההסרה נפתחה.");
        }

        // 1. נעילה יזומה מהשרת גוברת על הכול
        if (_remoteLockoutUntil is { } until)
        {
            if (DateTimeOffset.UtcNow < until)
                return (true, _remoteLockoutReason ?? "נעילה יזומה");

            _remoteLockoutUntil = null;
            _remoteLockoutReason = null;
        }

        // 2. רשת שאינה מאושרת
        //
        // גובר על מצב האכיפה: גם במצב ניטור, רשת שהשרת חסם
        // נחסמת. אחרת ההגדרה "התראה בלבד" הייתה מבטלת את כל
        // הרשימה הלבנה.
        if (_networkBlocked)
            return (true, _networkBlockReason ?? "הרשת אינה מאושרת.");

        // 3. חלון זמן מתוזמן מהמדיניות
        var localNow = DateTime.Now;
        var activeSchedule = policy.Enforcement.Schedules.FirstOrDefault(s => s.IsActiveAt(localNow));

        if (activeSchedule is not null)
            return (true, $"חסימה מתוזמנת ({activeSchedule.From}-{activeSchedule.To})");

        // 4. במצבי ניטור והתראה לא חוסמים בכלל
        if (policy.Enforcement.Mode != EnforcementMode.Enforce)
            return (false, "");

        /*
         * 5. סטטוס אדום עם פעולת נעילה מוגדרת.
         *
         * שתי קריאות רצופות, ולא אחת.
         *
         * ביקורת בודדת נכשלת מסיבות שאין להן קשר לסינון: המחשב
         * הרגע עלה והחיבור עוד לא התייצב, הרשת האלחוטית התחלפה,
         * שירות הכתובת הציבורית לא ענה. חסימה על סמך קריאה אחת
         * הופכת כל רעד ברשת לניתוק מלא — וכשהיא נסגרת, היא מונעת
         * את הבדיקה הבאה שהייתה משחררת אותה.
         *
         * Unknown אינו נספר כאן. הוא נספר רק כשהבדיקה רצה ואמרה
         * "אינו מסונן", ולא כשהיא לא הצליחה לרוץ.
         */
        if (snapshot.Status == SecurityStatus.Unfiltered &&
            policy.Enforcement.OnRedAction == RedAction.Lockout)
        {
            _consecutiveUnfiltered++;

            if (_consecutiveUnfiltered >= UnfilteredBeforeLockout)
                return (true, "החיבור אינו מסונן");

            _log.LogWarning(
                "החיבור אינו מסונן ({Count}/{Needed}). ממתין לאישור נוסף לפני חסימה.",
                _consecutiveUnfiltered, UnfilteredBeforeLockout);

            return (false, "");
        }

        // כל סטטוס אחר מאפס את המונה, כולל Unknown
        _consecutiveUnfiltered = 0;

        // 5. רשת אלחוטית שאינה ברשימה המותרת
        var allowedSsids = policy.Enforcement.AllowedNetworks.WifiSsids;

        if (allowedSsids.Count > 0 && snapshot.WifiSsid is { } ssid &&
            !allowedSsids.Contains(ssid, StringComparer.OrdinalIgnoreCase))
            return (true, $"הרשת האלחוטית {ssid} אינה מאושרת");

        return (false, "");
    }

    /// <summary>
    /// בונה תוכנית נעילה. הכתובות של שרת הניהול מיושבות מראש, כדי שהמחשב
    /// יישאר בקשר עם השרת גם כשה-DNS חסום.
    /// </summary>
    /// <summary>
    /// בונה את תוכנית ה-default-deny.
    ///
    /// שני דברים נעשים כאן ולא בתכנון עצמו, כי שניהם נוגעים במכונה:
    /// יישוב שמות שרת הניהול לכתובות, ואיתור הנתיבים של כלי המנהור.
    /// התכנון נשאר טהור ולכן נבדק בלי מכונה.
    /// </summary>
    private async Task<EnforcementPlan> BuildEgressPlanAsync(
        PolicyBundle policy, EgressRule egress, string? forcedReason, CancellationToken ct)
    {
        var allow = policy.Enforcement.AlwaysAllow;

        var hosts = allow.Hosts
            .Concat(_serverOptions.AlwaysAllowHosts)
            .Concat([new Uri(_serverOptions.BaseUrl).Host])
            .Distinct(StringComparer.OrdinalIgnoreCase);

        var serverIps = await WfpEnforcementEngine.ResolveServerIpsAsync(hosts, _log, ct);
        serverIps.AddRange(allow.Ips);

        var plan = EgressPlanner.Build(egress, new EgressPlanner.Context
        {
            ServerIps = serverIps.Distinct().ToList(),
            AgentPaths = [Environment.ProcessPath ?? ""],
            Detection = DetectionFrom(_state.Current),
            NetworkBlocked = _networkBlocked,
            Unmanaged = _serverOptions.Unmanaged,
            ForcedLockdownReason = forcedReason ?? (_networkBlocked ? _networkBlockReason : null)
        });

        /*
         * תרגום שמות הקבצים לנתיבים.
         *
         * WFP חוסם לפי נתיב, והמדיניות מגיעה עם שמות. האיתור נעשה
         * כאן, אחרי התכנון, כי הוא נוגע במערכת הקבצים — ומשום שהוא
         * עלול להחזיר רשימה ריקה לגמרי, מה שאסור שיפיל את התוכנית.
         */
        var paths = _tunnels.Locate(plan.BlockedProcessNames);

        return new EnforcementPlan
        {
            BlockAllOutbound = plan.BlockAllOutbound,
            Posture = plan.Posture,
            AllowedRemoteCidrs = plan.AllowedRemoteCidrs,
            AllowedPortRules = plan.AllowedPortRules,
            AllowedResolvers = plan.AllowedResolvers,
            ServerIps = plan.ServerIps,
            AllowedAppPaths = plan.AllowedAppPaths,
            AllowedPorts = plan.AllowedPorts,
            BlockedPorts = plan.BlockedPorts,
            BlockedRemoteCidrs = plan.BlockedRemoteCidrs,
            BlockedProcessNames = [.. paths],
            BlockAllInbound = plan.BlockAllInbound,
            AllowDns = plan.AllowDns,
            AllowDhcp = plan.AllowDhcp,
            AllowLoopback = plan.AllowLoopback,
            Reason = plan.Reason
        };
    }

    /// <summary>
    /// בונה זיהוי ספק מתמונת המצב.
    ///
    /// תמונת המצב היא מקור האמת המשותף, וכבר מכילה את תוצאת
    /// הביקורת האחרונה. שמירת עותק שני של אותו מידע רק כדי
    /// להעביר אותו לתכנון הייתה מקור אמת נוסף שיכול לסתור.
    /// </summary>
    private static ProviderDetection? DetectionFrom(StatusSnapshot snapshot)
        => snapshot.ProviderId is null
            ? null
            : new ProviderDetection
            {
                ProviderId = snapshot.ProviderId,
                DisplayName = snapshot.ProviderDisplayName ?? "",
                Trust = snapshot.ProviderTrust,
                PublicIp = snapshot.PublicIp,
                ReverseDns = snapshot.ReverseDns
            };

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
