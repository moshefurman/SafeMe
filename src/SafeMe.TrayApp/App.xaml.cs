using System.Windows;
using System.Windows.Markup;
using SafeMe.TrayApp.Services;
using SafeMe.TrayApp.Views;
using Application = System.Windows.Application;

namespace SafeMe.TrayApp;

public partial class App : Application
{
    /// <summary>מונע ריבוי מופעים באותו סשן משתמש.</summary>
    private static Mutex? _instanceMutex;

    private TrayIconHost? _tray;
    private StatusPoller? _poller;
    private ServiceGuardian? _guardian;
    private StatusBadge? _badge;
    private BadgeKeeper? _keeper;

    protected override void OnStartup(StartupEventArgs e)
    {
        // ה-Watchdog של השירות עלול להפעיל מופע נוסף לפני שהקודם נסגר לגמרי
        _instanceMutex = new Mutex(true, @"Local\SafeMe.TrayApp.SingleInstance", out var isFirst);

        if (!isFirst)
        {
            Shutdown();
            return;
        }

        // כל ממשקי SafeMe בעברית, ולכן כיוון הפריסה הוא מימין לשמאל כברירת מחדל
        FrameworkElement.LanguageProperty.OverrideMetadata(
            typeof(FrameworkElement),
            new FrameworkPropertyMetadata(XmlLanguage.GetLanguage("he-IL")));

        base.OnStartup(e);

        // מצב תצוגה מקדימה: מרנדר את התג לתמונה ויוצא. משמש לבדיקה
        // ולתיעוד, ואינו מפעיל שירותי רקע.
        var previewIndex = Array.FindIndex(e.Args, a => a == "--preview");

        if (previewIndex >= 0)
        {
            var path = previewIndex + 1 < e.Args.Length
                ? e.Args[previewIndex + 1]
                : "badge-preview.png";

            Views.BadgePreview.Write(path);
            Shutdown();

            return;
        }

        _poller = new StatusPoller();
        _tray = new TrayIconHost(_poller);
        _guardian = new ServiceGuardian(_poller);

        // התג הצף הוא המחוון הראשי. אייקון המגש נשאר כגיבוי, כי
        // ב-Windows 11 הוא מוסתר כברירת מחדל מאחורי חץ.
        _badge = new StatusBadge(_poller);
        BadgeActions.ShowStatusWindow = () => _tray?.ShowStatusWindow();
        _badge.Show();

        /*
         * השומר: בודק כל כמה שניות שהתג באמת גלוי, מתקן, ורושם מה
         * הסתיר אותו. "האייקון נעלם" חזר בשטח בעוד התהליך חי — בלי
         * הרישום הזה אין דרך לדעת מה קרה בין לבין.
         */
        _keeper = new BadgeKeeper(_badge, _badge.Reposition, _badge.Relayout);
        _keeper.Revived += () => _tray?.Revive();
        _keeper.Start();

        _poller.Start();
        _guardian.Start();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _keeper?.Dispose();
        _badge?.ShutdownAndClose();
        _guardian?.Dispose();
        _poller?.Dispose();
        _tray?.Dispose();
        _instanceMutex?.Dispose();

        base.OnExit(e);
    }
}
