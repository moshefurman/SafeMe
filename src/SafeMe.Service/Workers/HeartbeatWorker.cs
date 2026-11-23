using System.Reflection;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Audit;
using SafeMe.Core.Models;
using SafeMe.Service.Audit;
using SafeMe.Service.Net;
using SafeMe.Service.Diagnostics;
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
    private readonly HeartbeatSignal _signal;
    private readonly ServerOptions _options;

    /// <summary>לא נרשם בהזרקה: המצב שייך לפעימה בלבד, ואין לו צרכן אחר.</summary>
    private readonly NetworkIdentityTracker _networkIdentity = new();

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
        HeartbeatSignal signal,
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
        _signal = signal;
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

        /*
         * הערכה מיידית על מה שיש — גם אם השרת לא ענה.
         *
         * RefreshPolicyAsync קוראת ל-ReevaluateAsync רק כשהשרת
         * מחזיר מדיניות חדשה. כששרת Render ישן, הסוכן נשאר על
         * "מאתחל" עד שפעימה עתידית תצליח — ובינתיים אין אכיפה.
         *
         * ההערכה כאן מחילה את המדיניות השמורה (או ברירת המחדל) מיד,
         * כך שהתוסף, ה-DNS ורמת האגרס מתחילים לרוץ בלי לחכות לשרת.
         */
        await _enforcement.ReevaluateAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            await EnsureEnrolledAsync(stoppingToken);

            if (!_uninstall.Disarmed)
                await SendHeartbeatAsync(stoppingToken);

            var jitter = TimeSpan.FromSeconds(Random.Shared.Next(-15, 15));
            var delay = TimeSpan.FromSeconds(_options.HeartbeatSeconds) + jitter + _backoff;

            try
            {
                // המתנה שאפשר להעיר: בקשת רענון (כפתור במגש) קוטעת
                // את השינה ומוציאה את הפעימה הבאה מיד, במקום להמתין
                // עד שלוש דקות. פסק הזמן הרגיל נשאר גיבוי.
                var nudged = await _signal.WaitAsync(delay, stoppingToken);

                if (nudged)
                    _log.LogInformation("התקבלה בקשת רענון. מבצע פעימה מיידית.");
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
            UninstallPolicy = _options.UninstallPolicy,
            NetworkFloor = _options.NetworkFloor,
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

            /*
             * רישום מתחיל חיים חדשים, וגם היסטוריית ההסרה מתאפסת.
             *
             * הדגל מסמן ש-uninstall.dat כבר נוצר, ולכן היעדרו מכאן
             * והלאה הוא מחיקה. מחשב שנרשם מחדש הגיע לכאן בלי הקובץ
             * הזה — הרישום מתרחש רק כשאין אסימון, כלומר כשהמצב נמחק
             * או שזו התקנה ראשונה.
             *
             * בלי האיפוס, דגל ששרד בזיכרון הופך את ניסיון ההסרה הבא
             * לחבלה לכאורה, ונועל את המסך לרבע שעה בלי שהיה ניסיון.
             */
            state.UninstallStateInitialized = false;
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

    /// <summary>
    /// מעבר לקוד הסרה קצר, כשהשרת מציע אותו.
    ///
    /// מחשב שנרשם לפני שהייתה גזירת סודות מאמת ב-RSA, וקוד ההסרה
    /// שלו הוא חתימה בת שש מאות תווים. זה עובד כשמדביקים, ואי אפשר
    /// להכתיב את זה בטלפון — כלומר מסלול המוקד אינו שמיש בדיוק
    /// במצב שבשבילו הוא קיים.
    ///
    /// הרישום לא יקרה שוב: הוא מותנה בהיעדר אסימון, והתקנה מעל
    /// התקנה קיימת שומרת עליו. לכן המעבר חייב לקרות כאן.
    /// </summary>
    private void ApplyUninstallKeyUpgrade(HeartbeatResponse response)
    {
        if (response.UninstallKeyMode is not { } mode) return;

        /*
         * שני התנאים ביחד, ולא כל אחד לחוד.
         *
         * מצב בלי סוד היה משאיר מחשב שמצפה ל-HMAC ואין לו במה
         * לאמת — כלומר נעילה מוחלטת, שגרועה מקוד ארוך. סוד בלי
         * מצב הוא בתים שאיש לא יקרא.
         */
        if (mode != UninstallKeyMode.Hmac || string.IsNullOrWhiteSpace(response.DeviceSecret))
        {
            _log.LogWarning("השרת הציע שדרוג קוד הסרה חלקי. נדחה, והמצב הקיים נשמר.");
            return;
        }

        /*
         * אימות שהבתים ניתנים לפענוח לפני השמירה.
         *
         * סוד פגום שנשמר היה מתגלה רק ברגע ההסרה, כשההורה כבר על
         * הקו עם המוקד — ואז גם הקוד הישן כבר לא תקף. עדיף להישאר
         * ב-RSA.
         */
        try
        {
            if (Convert.FromBase64String(response.DeviceSecret).Length == 0)
                throw new FormatException("סוד ריק");
        }
        catch (FormatException)
        {
            _log.LogError("סוד ההסרה שהתקבל אינו תקין. המצב הקיים נשמר.");
            return;
        }

        var device = _deviceStore.Load();

        if (device.UninstallKeyMode == UninstallKeyMode.Hmac
            && device.DeviceSecretBase64 == response.DeviceSecret) return;

        _deviceStore.Update(state =>
        {
            state.UninstallKeyMode = UninstallKeyMode.Hmac;
            state.DeviceSecretBase64 = response.DeviceSecret;
        });

        _log.LogInformation("קוד ההסרה שודרג לקוד קצר שאפשר להכתיב בטלפון.");
    }

    /// <summary>
    /// אוסף יומן אבחון ושולח אותו, בעקבות בקשה מהפורטל.
    ///
    /// האיסוף עצמו לוקח שניות — קריאת יומן אירועים על מחשב עמוס
    /// אינה מיידית — ולכן הוא רץ בתוך ביצוע הפקודה ולא חוסם את
    /// הפעימה הבאה: הפקודות מבוצעות אחרי שהתשובה כבר התקבלה.
    ///
    /// כישלון נרשם ואינו נזרק. יומן שלא הגיע הוא הטרדה; פעימה
    /// שנפלה בגללו היא מחשב ששותק.
    /// </summary>
    private async Task CollectAndSendLogsAsync(Guid commandId, CancellationToken ct)
    {
        byte[] bundle;

        try
        {
            bundle = LogBundle.Collect(AgentVersion);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "איסוף יומן האבחון נכשל.");
            return;
        }

        _log.LogWarning(
            "נאסף יומן אבחון לבקשת התמיכה ({Kb:N0} ק\"ב דחוס). נשלח לשרת.",
            bundle.Length / 1024.0);

        if (!await _server.SendLogBundleAsync(bundle, commandId, ct))
            _log.LogWarning("שליחת יומן האבחון נכשלה. הבקשה תישאר פתוחה עד לפקיעתה.");
    }

    /// <summary>
    /// מחיל היתר להורדת רצפה, אם התקבל.
    ///
    /// הסוכן אינו סומך על כך שהשרת בדק: הוא מאמת חתימה במפתח
    /// ההיתרים, מוודא שהמפתח נפרד ממפתח המדיניות, ובודק nonce,
    /// תוקף, והתאמה לרצפה הנוכחית. כל זה כבר היה כתוב ב-PolicyStore
    /// ולא היה מי שיקרא לו.
    ///
    /// הפרדת המפתחות היא כל ההגנה כאן: שרת שנפרץ ויכול לחתום
    /// מדיניות אינו יכול בכך גם להוריד רצפות.
    /// </summary>
    private void ApplyLooseningGrant(HeartbeatResponse response, DeviceState device)
    {
        if (response.LooseningGrant is not { } envelope) return;

        var applied = _policyStore.ApplyLooseningGrant(
            envelope,
            device.LooseningPublicKeyPem,
            device.ServerPublicKeyPem,
            _hwid.GetHardwareId());

        if (applied)
        {
            _log.LogWarning("התקבל היתר חתום והרצפה הורדה. האכיפה עשויה להשתנות.");
        }
        else
        {
            /*
             * היתר שנדחה הוא אירוע ביטחוני, לא רעש.
             *
             * הוא אומר שמישהו ניסה להוריד רצפה בלי היתר תקף — או
             * שהמפתחות התבלבלו, וזה בדיוק מה שצריך להתגלות מיד
             * ולא בעוד חודש.
             */
            _log.LogError("היתר הקלה נדחה. הרצפה נשארת כפי שהיא.");

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.PolicySignatureInvalid,
                Detail = "היתר להורדת רצפה נדחה באימות."
            });
        }
    }

    private async Task RefreshPolicyAsync(CancellationToken ct)
    {
        var device = _deviceStore.Load();

        /*
         * מחשב בלי מדיניות אינו מציג סימן שיש לו אחת.
         *
         * הרישום מחזיר PolicyEtag והסוכן שמר אותו — ואז המשיכה
         * הראשונה שלחה אותו, השרת ענה "לא השתנה", והסוכן חזר בלי
         * כלום. הדיסק היה ריק, וה-ETag כבר תאם, ולכן שום פעימה
         * עתידית לא משכה שוב: התנאי בפעימה משווה ETag לזה ששמור.
         *
         * התוצאה היא סוכן שרץ לנצח על מדיניות ברירת המחדל, בלי
         * כללי זיהוי — כלומר מדווח "לא זוהה ספק מאושר" על מחשב
         * מסונן לחלוטין. זה מה שנצפה בשטח אחרי התקנה נקייה.
         *
         * Version אפס הוא בדיוק "ברירת המחדל", כי CreateDefault
         * מייצר אותה עם אפס וכל מדיניות מהשרת גדולה ממנה.
         */
        var etag = _policyStore.Current.Version > 0 ? device.PolicyEtag : null;

        /*
         * וגם אחרי שדרוג.
         *
         * המדיניות שעל הדיסק נשמרה על ידי הגרסה הקודמת, בלי השדות
         * שהיא לא הכירה. הרשימה הלבנה היא שדה כזה: הורה שהפעיל אותה
         * לפני שהמחשב התעדכן היה מקבל מחשב מעודכן שאינו יודע עליה,
         * עד השינוי הבא במדיניות.
         */
        if (device.PolicyFetchedByVersion != AgentVersion)
        {
            if (etag is not null)
                _log.LogWarning("המדיניות השמורה נמשכה בגרסה אחרת של הסוכן. מושך אותה מחדש במלואה.");

            etag = null;
        }
        else if (etag is null && device.PolicyEtag is not null)
        {
            _log.LogWarning(
                "קיים סימן מדיניות אך אין מדיניות שמורה. מושך את המדיניות במלואה.");
        }

        var response = await _server.GetPolicyAsync(etag, ct);

        if (response.NotModified || response.Envelope is null) return;

        // נרשם ברגע שהשרת ענה, גם אם המדיניות תידחה: משיכה שנדחית
        // אינה סיבה למשוך שוב בכל פעימה ולדווח את אותה דחייה כל שלוש דקות.
        _deviceStore.Update(state => state.PolicyFetchedByVersion = AgentVersion);

        var outcome = _policyStore.AcceptEnvelope(response.Envelope, device.ServerPublicKeyPem);

        if (outcome.Accepted)
        {
            _deviceStore.Update(state =>
            {
                state.PolicyEtag = response.Etag;
                state.PolicyFetchedByVersion = AgentVersion;
            });

            await _enforcement.ReevaluateAsync(ct);

            return;
        }

        // דחיית מדיניות היא תמיד אירוע שדורש דיווח. מדיניות שמנסה להקל
        // מתחת לרצפה חשודה במיוחד: היא עלולה להעיד על שרת פרוץ.
        var detail = outcome.LooseningReasons.Count > 0
            ? $"מדיניות נדחתה כמקלה מתחת לרצפה: {string.Join(" | ", outcome.LooseningReasons)}"
            : $"מדיניות נדחתה ({outcome.Status}): {outcome.Message}";

        /*
         * וגם ליומן המקומי, ולא רק לשרת.
         *
         * עד כאן הסיבה נשלחה כאירוע חבלה ונעלמה מהמחשב
         * עצמו. מי שעמד מול סוכן שתקוע על מדיניות ישנה ראה שתיקה
         * מוחלטת: הפעימה עובדת, המספר בפורטל עולה, והמספר
         * במחשב עומד — בלי שום רמז למה.
         *
         * ברמת אזהרה ולא מידע, כי יומן האירועים של Windows
         * מקבל אזהרות ומעלה בלבד.
         */
        _log.LogWarning("{Detail}", detail);

        _events.Enqueue(new TamperEvent
        {
            Kind = TamperKind.PolicySignatureInvalid,
            Detail = detail
        });
    }

    private async Task SendHeartbeatAsync(CancellationToken ct)
    {
        var snapshot = _state.Current;
        var device = _deviceStore.Load();

        if (string.IsNullOrEmpty(device.DeviceToken)) return;
        var pending = _events.DrainAll();

        /*
         * ספק האינטרנט, בפעימה ולא בביקורת.
         *
         * הוא צריך להיקרא לעיתים קרובות יותר ממה שהביקורת רצה,
         * כי החלפת קו מאחורי אותו נתב היא בדיוק מה שהוא אמור
         * לתפוס — ואם הוא היה נקרא רק בביקורת, שום דבר לא היה
         * מעיר אותה כדי לגלות זאת. תלות מעגלית: הביקורת הייתה
         * המקום היחיד שיודע, והדבר היחיד שמעיר אותה.
         *
         * המחיר הוא בקשה קטנה אחת לכל שלוש דקות.
         */
        var isp = await _network.GetIspAsync(ct);

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
            IspKey = isp.Key,
            IspName = isp.Name,
            FailedProbes = snapshot.FailedProbes.Select(p => p.Id).ToList(),
            TamperEvents = pending,
            WfpFilterCount = snapshot.WfpFilterCount,
            UptimeSec = snapshot.UptimeSeconds,
            LockoutActive = snapshot.LockoutActive,

            // מה שהוחל בפועל. השרת מעדכן את הרצפה הרשומה לפי זה בלבד.
            AppliedGrantNonces = _policyStore.UsedGrantNonces.ToList()
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

        // מה שנצפה בלמידה יוצא עם כל פעימה שהצליחה.
        await _enforcement.ReportObservedAsync(_server, ct);


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

        /*
         * ורשת חדשה מחייבת ביקורת חדשה.
         *
         * הביקורת רצה על שעון של רבע שעה, ואף אחד לא העיר אותה
         * כשהמחשב עבר רשת. התוצאה נצפתה בשטח: ניתוק מרימון,
         * והסוכן ממשיך להציג "מוגן · רימון · בסיסית" עד הביקורת
         * הבאה. הנתון היה נכון, והשאלה שהוא ענה עליה כבר לא.
         *
         * הפעימה היא המקום הנכון: היא כבר מחשבת את זהות הרשת
         * עבור ההכרעה, ורצה כל שלוש דקות — כך שהחלון המרבי
         * מתקצר מרבע שעה לשלוש דקות.
         *
         * והזהות לצורך הזה כוללת את ספק האינטרנט, בניגוד לזהות
         * שההכרעה נקשרת אליה למעלה. החלפת קו מאחורי אותו נתב אינה
         * משנה שם, שער, או כתובת חומרה — ובלי הספק היא הייתה עוברת
         * בלי שאיש יבחין.
         *
         * ספק שלא נקרא מוליד זהות ריקה, ולא זהות שלישית. הקריאה
         * יוצאת לרשת ונכשלת בדיוק כשהרשת חסומה, ומזהה שמתחלף עם
         * כל כישלון היה מריץ ביקורות בלי סוף.
         */
        var identityWithIsp = current is not null && isp.IsKnown
            ? $"{current}|{isp.Key}"
            : null;

        if (_networkIdentity.Changed(identityWithIsp))
        {
            _log.LogWarning("הרשת או ספק האינטרנט התחלפו. מריץ ביקורת מיידית במקום להמתין למחזור הבא.");
            await _auditWorker.RunOnceAsync(ct);
        }

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

        ApplyLooseningGrant(response, device);

        ApplyUninstallKeyUpgrade(response);

        // גם כשהמשיכה שאחרי שדרוג עוד לא הצליחה: היא מנוסה שוב בכל פעימה.
        if ((!string.IsNullOrEmpty(response.PolicyEtag) && response.PolicyEtag != device.PolicyEtag)
            || device.PolicyFetchedByVersion != AgentVersion)
        {
            await RefreshPolicyAsync(ct);
        }

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
        /*
         * ההורדה עברה לרקע, ולכן אין כאן מה להמתין לו.
         *
         * השורה "עדכון הוחל" עברה ל-UpdateWorker, למקום שבו
         * זה באמת קורה. כאן היא הייתה מדווחת על התחלה שעוד
         * עשויה להיכשל.
         */
        _updates.TryApply(response.Update, DateTimeOffset.UtcNow, ct);
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

                case "CollectLogs":
                    await CollectAndSendLogsAsync(command.Id, ct);
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
