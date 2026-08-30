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
/// מריץ ביקורת תקופתית, מעדכן את תמונת המצב, ומפעיל הערכה מחדש של האכיפה.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuditWorker : BackgroundService
{
    /*
     * הגרסה נקראת מהאסמבלי ולא ממחרוזת קבועה.
     *
     * הייתה ברירת מחדל "1.0.0" ב-StatusSnapshot שאיש לא דרס, ולכן
     * המסך הראה 1.0.0 בכל גרסה. HeartbeatWorker כבר קרא את הערך
     * הנכון ושלח אותו לשרת — הוא פשוט מעולם לא הגיע למסך.
     */
    private static readonly string AgentVersion =
        System.Reflection.Assembly.GetExecutingAssembly()
            .GetName().Version?.ToString(3) ?? "";

    private readonly ILogger<AuditWorker> _log;
    private readonly AuditEngine _audit;
    private readonly IAgentStateProvider _state;
    private readonly EnforcementCoordinator _enforcement;
    private readonly IManagementServerClient _server;
    private readonly UninstallCoordinator _uninstall;
    private readonly ServerOptions _options;

    public AuditWorker(
        ILogger<AuditWorker> log,
        AuditEngine audit,
        IAgentStateProvider state,
        EnforcementCoordinator enforcement,
        IManagementServerClient server,
        UninstallCoordinator uninstall,
        IOptions<ServerOptions> options)
    {
        _log = log;
        _audit = audit;
        _state = state;
        _enforcement = enforcement;
        _server = server;
        _uninstall = uninstall;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // השהיה קצרה בהתחלה: נותנת למחסנית הרשת להתייצב אחרי עליית המערכת
        await SafeDelay(TimeSpan.FromSeconds(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_uninstall.Disarmed)
            {
                await SafeDelay(TimeSpan.FromMinutes(5), stoppingToken);
                continue;
            }

            await RunOnceAsync(stoppingToken);

            // פיזור אקראי קטן מונע מכל התחנות בארגון לבקר באותו רגע
            var jitter = TimeSpan.FromSeconds(Random.Shared.Next(-30, 30));

            await SafeDelay(TimeSpan.FromMinutes(_options.AuditMinutes) + jitter, stoppingToken);
        }
    }

    public async Task RunOnceAsync(CancellationToken ct)
    {
        try
        {
            _enforcement.RefreshNetworkInfo();

            var report = await _audit.RunAsync(_state.Current.LockoutActive, ct);

            _state.Update(s =>
            {
                // בזמן נעילה פעילה הסטטוס נשלט על ידי רכיב האכיפה ולא על ידי הביקורת
                if (!s.LockoutActive)
                {
                    s.Status = report.Status;
                    s.Headline = report.Headline;
                }

                s.Score = report.Score;
                s.ProviderId = report.Detection.ProviderId;
                s.ProviderDisplayName = report.Detection.DisplayName;
                /*
                 * שינוי ברמת ההגנה נרשם כאזהרה ולא כמידע.
                 *
                 * יומן האירועים של Windows מקבל אזהרות ומעלה בלבד, ולכן
                 * שורת הסיכום של הביקורת — שנכתבת ברמת מידע — אינה
                 * מופיעה בו כלל. כל האבחון שנבנה שם היה בלתי נראה
                 * בדיוק כשהיה צריך אותו.
                 *
                 * רק בשינוי, ולא בכל ביקורת: רישום כל שלוש דקות היה
                 * קובר את מה שבאמת קרה.
                 *
                 * וההשוואה **לפני** ההשמה. היא ישבה אחריה, ולכן שני
                 * הצדדים היו אותו ערך והתנאי לא התקיים לעולם —
                 * אבחון שנכתב, נבנה, ולא יכול היה לירות אף פעם.
                 */
                var was = s.FilterLevel?.Name ?? s.FilterLevel?.Account?.ToString();
                var now = report.Detection.FilterLevel?.Name
                    ?? report.Detection.FilterLevel?.Account?.ToString();

                if (was != now)
                {
                    _log.LogWarning(
                        "רמת ההגנה השתנתה: {Was} ← {Now}.",
                        was ?? "לא נקראה", now ?? "לא נקראה");
                }

                s.FilterLevel = report.Detection.FilterLevel;
                s.ProviderTrust = report.Detection.Trust;
                s.PublicIp = report.Detection.PublicIp;
                s.ReverseDns = report.Detection.ReverseDns;
                s.PolicyVersion = report.PolicyVersion;
                s.AgentVersion = AgentVersion;

                s.LastAuditUtc = report.CompletedUtc;

                s.FailedProbes = report.Failures
                    .Select(f => new ProbeSummary
                    {
                        Id = f.ProbeId,
                        Title = f.Title ?? f.ProbeId,
                        Severity = f.Severity,
                        Detail = f.Detail
                    })
                    .ToList();
            });

            await _enforcement.ReevaluateAsync(ct);
            await _server.SendAuditAsync(report, ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "מחזור ביקורת נכשל.");
        }
    }

    private static async Task SafeDelay(TimeSpan delay, CancellationToken ct)
    {
        try
        {
            await Task.Delay(delay, ct);
        }
        catch (OperationCanceledException)
        {
            // כיבוי מסודר
        }
    }
}
