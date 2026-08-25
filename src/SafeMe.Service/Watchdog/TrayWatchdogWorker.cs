using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SafeMe.Core.Models;
using SafeMe.Service.Workers;

namespace SafeMe.Service.Watchdog;

/// <summary>
/// הצד של השירות ב-Watchdog הכפול: מוודא שלכל משתמש מחובר רץ אייקון מגש,
/// ומחיה אותו אם נסגר.
///
/// הצד השני נמצא ב-TrayApp, שמוודא שהשירות רץ. שני הצדדים יחד מייצרים
/// מצב שבו הריגה של אחד מהם אינה משאירה את המערכת ללא נראות.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TrayWatchdogWorker : BackgroundService
{
    private const string TrayProcessName = "SafeMe.TrayApp";

    /// <summary>תדירות הבדיקה. חמש שניות נותנות התאוששות מהירה בלי עומס מיותר.</summary>
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(5);

    /// <summary>השהיה לפני החייאה חוזרת, כדי לא להיכנס ללולאת הפעלה כושלת.</summary>
    private static readonly TimeSpan RelaunchCooldown = TimeSpan.FromSeconds(20);

    private readonly ILogger<TrayWatchdogWorker> _log;
    private readonly SessionLauncher _launcher;
    private readonly EventQueue _events;
    private readonly UninstallCoordinator _uninstall;

    private readonly Dictionary<uint, DateTimeOffset> _lastLaunchAttempt = new();
    private readonly HashSet<uint> _reportedSessions = [];

    public TrayWatchdogWorker(
        ILogger<TrayWatchdogWorker> log,
        EventQueue events,
        UninstallCoordinator uninstall,
        ILoggerFactory loggerFactory)
    {
        _log = log;
        _events = events;
        _uninstall = uninstall;
        _launcher = new SessionLauncher(loggerFactory.CreateLogger<SessionLauncher>());
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var trayPath = ResolveTrayPath();

        if (trayPath is null)
        {
            _log.LogError("לא נמצא קובץ ההרצה של אייקון המגש. ה-Watchdog מושבת.");
            return;
        }

        _log.LogInformation("Watchdog של אייקון המגש פעיל. נתיב: {Path}", trayPath);

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!_uninstall.Disarmed)
                EnsureTrayRunning(trayPath);

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

    private void EnsureTrayRunning(string trayPath)
    {
        try
        {
            var sessions = _launcher.GetActiveUserSessions();
            var runningSessions = GetSessionsRunningTray();

            foreach (var session in sessions)
            {
                if (runningSessions.Contains(session))
                {
                    _reportedSessions.Remove(session);
                    continue;
                }

                if (_lastLaunchAttempt.TryGetValue(session, out var last) &&
                    DateTimeOffset.UtcNow - last < RelaunchCooldown)
                    continue;

                _lastLaunchAttempt[session] = DateTimeOffset.UtcNow;

                // מדווחים פעם אחת לכל סשן, כדי שסגירה חוזרת לא תציף את השרת
                if (_reportedSessions.Add(session))
                {
                    _events.Enqueue(new TamperEvent
                    {
                        Kind = TamperKind.TrayAppKilled,
                        Detail = $"אייקון המגש אינו פעיל בסשן {session}. מתבצעת החייאה."
                    });
                }

                _launcher.LaunchInSession(session, trayPath);
            }

            // ניקוי סשנים שכבר אינם קיימים
            foreach (var stale in _lastLaunchAttempt.Keys.Except(sessions).ToList())
                _lastLaunchAttempt.Remove(stale);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "בדיקת Watchdog של אייקון המגש נכשלה.");
        }
    }

    /// <summary>מזהי הסשנים שבהם כבר רץ אייקון מגש.</summary>
    private static HashSet<uint> GetSessionsRunningTray()
    {
        var sessions = new HashSet<uint>();

        foreach (var process in Process.GetProcessesByName(TrayProcessName))
        {
            try
            {
                sessions.Add((uint)process.SessionId);
            }
            catch (Exception)
            {
                // התהליך הסתיים בין המנייה לקריאה
            }
            finally
            {
                process.Dispose();
            }
        }

        return sessions;
    }

    /// <summary>מאתר את קובץ ההרצה של אייקון המגש ליד קובץ השירות.</summary>
    private static string? ResolveTrayPath()
    {
        var baseDir = AppContext.BaseDirectory;

        string[] candidates =
        [
            Path.Combine(baseDir, "SafeMe.TrayApp.exe"),
            Path.Combine(baseDir, "..", "TrayApp", "SafeMe.TrayApp.exe"),
            Path.Combine(Directory.GetParent(baseDir)?.FullName ?? baseDir, "SafeMe.TrayApp.exe")
        ];

        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
    }
}
