using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Service.State;

namespace SafeMe.Service.Workers;

/// <summary>
/// שומר על שלמות האכיפה ומונע מצב של נעילה בלתי הפיכה.
///
/// שתי אחריות:
///   1. אימות שחוקי ה-WFP עדיין קיימים; מחיקה ידנית מטופלת כחבלה ובנייה מחדש.
///   2. דיווח על ניתוק ממושך מהשרת. שים לב: הניתוק **אינו** מרפה את
///      האכיפה. הגרסה הקודמת שחררה נעילה אוטומטית אחרי חלון החסד,
///      וזו הייתה דרך עקיפה זולה — די היה לחסום את השרת ולהמתין.
///      במקומה, כל נעילה נושאת זמן סיום משלה שהמכשיר סופר לבד.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IntegrityWorker : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);

    private readonly ILogger<IntegrityWorker> _log;
    private readonly IEnforcementEngine _engine;
    private readonly IAgentStateProvider _state;
    private readonly EnforcementCoordinator _enforcement;
    private readonly PolicyStore _policy;
    private readonly DeviceStateStore _deviceStore;
    private readonly EventQueue _events;
    private readonly UninstallCoordinator _uninstall;

    private bool _graceReported;

    public IntegrityWorker(
        ILogger<IntegrityWorker> log,
        IEnforcementEngine engine,
        IAgentStateProvider state,
        EnforcementCoordinator enforcement,
        PolicyStore policy,
        DeviceStateStore deviceStore,
        EventQueue events,
        UninstallCoordinator uninstall)
    {
        _log = log;
        _engine = engine;
        _state = state;
        _enforcement = enforcement;
        _policy = policy;
        _deviceStore = deviceStore;
        _events = events;
        _uninstall = uninstall;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (!_uninstall.Disarmed)
            {
                CheckWfpIntegrity();
                ReportProlongedDisconnect();
            }

            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void CheckWfpIntegrity()
    {
        try
        {
            if (_engine.VerifyIntegrity())
            {
                _state.Update(s => s.WfpFilterCount = _engine.ActiveFilterCount);
                return;
            }

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.WfpFiltersMissing,
                Detail = "חוקי WFP נמחקו מחוץ לסוכן. מתבצעת בנייה מחדש."
            });

            // בנייה מחדש מהמצב הרצוי, ולא ניסיון לתקן הפרשים
            _ = _enforcement.ReevaluateAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "בדיקת שלמות חוקי WFP נכשלה.");
        }
    }

    /// <summary>
    /// מדווח על ניתוק ממושך מהשרת. אינו משנה את מצב האכיפה.
    ///
    /// מכשיר שמנותק שבוע ממשיך לאכוף בדיוק את מה שידע. זו התנהגות
    /// מכוונת: ההגנה אינה תלויה בזמינות השרת.
    /// </summary>
    private void ReportProlongedDisconnect()
    {
        var device = _deviceStore.Load();
        var lastContact = device.LastServerContactUtc;

        // מכשיר שמעולם לא יצר קשר עדיין בתהליך התקנה
        if (lastContact is null) return;

        var offlineFor = DateTimeOffset.UtcNow - lastContact.Value;
        var grace = TimeSpan.FromMinutes(_policy.Current.GraceMinutes);

        if (offlineFor <= grace)
        {
            _graceReported = false;
            return;
        }

        if (_graceReported) return;

        _graceReported = true;

        _log.LogWarning(
            "אין קשר לשרת כבר {Hours:F1} שעות. האכיפה נמשכת כרגיל.",
            offlineFor.TotalHours);

        _events.Enqueue(new TamperEvent
        {
            Kind = TamperKind.ServiceCrash,
            Detail = $"נותק מהשרת {offlineFor.TotalHours:F1} שעות. האכיפה נשמרה."
        });
    }
}
