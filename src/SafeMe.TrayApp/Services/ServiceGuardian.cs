using System.Diagnostics;
using System.ServiceProcess;

namespace SafeMe.TrayApp.Services;

/// <summary>
/// הצד של אפליקציית המגש ב-Watchdog הכפול.
///
/// בודק שהשירות רץ, ומנסה להפעילו מחדש. משתמש רגיל אינו רשאי להפעיל שירות,
/// ולכן נעשה ניסיון ישיר ואם הוא נדחה מוצגת בקשת הרמה חד-פעמית.
/// אין ניסיון להסתיר את הפעולה מהמשתמש.
/// </summary>
public sealed class ServiceGuardian : IDisposable
{
    private const string ServiceName = "SafeMeAgent";

    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(10);

    /// <summary>מרווח מינימלי בין ניסיונות הפעלה, למניעת לולאת בקשות UAC.</summary>
    private static readonly TimeSpan RestartCooldown = TimeSpan.FromMinutes(2);

    private readonly StatusPoller _poller;
    private readonly CancellationTokenSource _cts = new();

    private DateTimeOffset _lastRestartAttempt = DateTimeOffset.MinValue;
    private Task? _loop;

    public ServiceGuardian(StatusPoller poller) => _poller = poller;

    public void Start() => _loop ??= Task.Run(() => LoopAsync(_cts.Token));

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!IsServiceRunning() && CanAttemptRestart())
                    TryStartService();
            }
            catch (Exception)
            {
                // בדיקת שירות היא מאמץ מיטבי; כשל בה לא מפיל את אפליקציית המגש
            }

            try
            {
                await Task.Delay(CheckInterval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public static bool IsServiceRunning()
    {
        try
        {
            using var controller = new ServiceController(ServiceName);
            return controller.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;
        }
        catch (InvalidOperationException)
        {
            // השירות אינו מותקן
            return false;
        }
    }

    private bool CanAttemptRestart() =>
        DateTimeOffset.UtcNow - _lastRestartAttempt > RestartCooldown;

    private void TryStartService()
    {
        _lastRestartAttempt = DateTimeOffset.UtcNow;

        try
        {
            using var controller = new ServiceController(ServiceName);

            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));

            return;
        }
        catch (Exception)
        {
            // צפוי כשהמשתמש אינו מנהל. עוברים לבקשת הרמה.
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"start {ServiceName}",
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            Process.Start(psi);
        }
        catch (Exception)
        {
            // המשתמש ביטל את בקשת ההרשאה. הסטטוס יישאר אפור וידווח לשרת.
        }
    }

    public void Dispose()
    {
        _cts.Cancel();

        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // סגירה בכל מקרה
        }

        _cts.Dispose();
    }
}
