using System.Runtime.Versioning;
using System.Windows;

using SafeMe.Installer.Views;

namespace SafeMe.Installer;

/// <summary>
/// נקודת הכניסה הגרפית.
///
/// היא אינה מוגדרת כ-StartupUri בקובץ ה-XAML, כי החלון צריך את
/// האסימון לפני שהוא נבנה — ומפני שיש מקרה שבו אין חלון בכלל:
/// כשאין אסימון, מה שנכון להציג הוא הסבר איך להשיג אותו ולא מסך
/// התקנה שאי אפשר להתקדם בו.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class App : Application
{
    private readonly string[] _args;

    public App(string[] args) => _args = args;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var token = InstallEngine.FindToken(_args);

        if (token is null)
        {
            ShowMissingToken();
            Shutdown(2);

            return;
        }

        var window = new InstallWindow(token, InstallEngine.FindServer(_args));

        window.ShowDialog();

        Shutdown(window.ExitCode);
    }

    /// <summary>
    /// אין אסימון.
    ///
    /// הסיבה השכיחה היא ששם הקובץ שונה — הורדה חוזרת מהדפדפן
    /// מוסיפה "(1)" ושוברת את התבנית. ההסבר מכוון לשם, כי זה מה
    /// שהמשתמש יכול לתקן בעצמו.
    /// </summary>
    private static void ShowMissingToken()
        => MessageBox.Show(
            "לא נמצא קוד התקנה.\n\n"
            + "הקובץ שהורדת אמור להיקרא כך:\n"
            + "SafeMe-Setup-ENR-XXXXXXXXXXXXXXXXXXXXXXXX.exe\n\n"
            + "אם שם הקובץ השתנה — למשל נוסף לו \"(1)\" בהורדה חוזרת — "
            + "הורד אותו מחדש מהאתר, או שנה את שמו בחזרה.",
            "התקנת SafeMe",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
}
