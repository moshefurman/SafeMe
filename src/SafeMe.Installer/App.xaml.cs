using System.Runtime.Versioning;
using System.Windows;

using SafeMe.Installer.Views;

namespace SafeMe.Installer;

/// <summary>
/// נקודת הכניסה הגרפית.
///
/// היא אינה מוגדרת כ-StartupUri בקובץ ה-XAML, כי החלון צריך את
/// האסימון לפני שהוא נבנה — וכשאין אסימון, המסך הראשון הוא בכלל
/// אחר: בחירה בין הזנת הקוד לבין חסימה מוחלטת בלי חשבון.
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

        /*
         * מחשב שכבר רשום מדלג על השאלה.
         *
         * הקוד נדרש לרישום ראשון בלבד. שדרוג אינו רישום — הזהות
         * כבר קיימת בקובץ המצב, וההתקנה אינה נוגעת בו. בקשת קוד
         * כאן שלחה את המשתמש לחפש קישור שאין לו שום צורך בו.
         */
        var upgrade = token is null && InstallEngine.IsAlreadyEnrolled();

        if (upgrade) token = "";

        // אין קוד וזו התקנה ראשונה. שואלים, במקום להיכשל.
        if (token is null)
        {
            var chooser = new ChooseModeWindow();

            chooser.ShowDialog();

            switch (chooser.Mode)
            {
                case ChosenMode.Enroll:
                    token = chooser.Token;
                    break;

                case ChosenMode.Seal:
                    /*
                     * מחרוזת ריקה, ולא null.
                     *
                     * ההבחנה נושאת משמעות: null פירושו "לא נבחר
                     * דבר", וריק פירושו "נבחר במפורש להתקין בלי
                     * חשבון". איחוד השניים היה הופך שכחה לבחירה.
                     */
                    token = "";
                    break;

                default:
                    Shutdown(2);
                    return;
            }
        }

        var window = new InstallWindow(token, InstallEngine.FindServer(_args), upgrade);

        window.ShowDialog();

        Shutdown(window.ExitCode);
    }
}
