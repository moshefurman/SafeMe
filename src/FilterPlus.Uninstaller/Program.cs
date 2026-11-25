using System.Runtime.Versioning;

namespace FilterPlus.Uninstaller;

/// <summary>
/// נקודת הכניסה.
///
/// היא קיימת כדי שיהיה אפשר לקרוא ארגומנטים לפני שנפתח חלון:
/// המסלול חסר-החלון נועד לבדיקות אוטומטיות, וחלון שנפתח לרגע
/// ונסגר הוא בדיוק מה שהופך בדיקה כזו לבלתי אפשרית.
///
/// בלי ארגומנטים ההתנהגות זהה לחלוטין למה שהייתה: חלון ההסרה
/// נפתח, וזה מה שמשתמש רואה.
/// </summary>
[SupportedOSPlatform("windows")]
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (Headless.Requested(args)) return Headless.Run(args);

        var app = new App();

        app.InitializeComponent();

        return app.Run();
    }
}
