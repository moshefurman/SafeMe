using FilterPlus.Installer;
using FilterPlus.Installer.Views;

namespace FilterPlus.Tests;

/// <summary>
/// שלושת מצבי ההתקנה.
///
/// עד כאן היו שניים — יש אסימון או אין — ו"אין" פירושו היה חסימה
/// מוחלטת של המחשב. שדרוג נפל בדיוק לשם: המתקין שהעדכון האוטומטי
/// מריץ אינו מקבל אסימון, כי אין לו ואין לו צורך באחד.
///
/// כלומר הבאג לא היה "העדכון לא עובד" אלא משהו גרוע בהרבה: עדכון
/// שהיה מצליח לרוץ היה חוסם לחלוטין מחשב שהיה מנוהל כהלכה, וההסרה
/// שלו הייתה מחייבת קוד מהמוקד.
///
/// שלושת המצבים חייבים להישאר נפרדים, ולכן הם נבדקים.
/// </summary>
[Collection("wpf")]
public sealed class InstallModeTests
{
    private readonly WpfHost _host;

    public InstallModeTests(WpfHost host) => _host = host;

    /// <summary>אסימון אמיתי: רישום לחשבון, בלי חסימה.</summary>
    [Fact]
    public void TokenMeansEnrolment()
        => _host.Run(() =>
        {
            var window = new InstallWindow("ENR-0123456789ABCDEF", "https://api.test");

            Assert.False(IsSealed(window));
        });

    /// <summary>
    /// אין אסימון והמשתמש בחר במפורש: חסימה מוחלטת.
    /// זו הבחירה שקיימת, והיא חייבת להמשיך לעבוד.
    /// </summary>
    [Fact]
    public void EmptyTokenMeansTotalBlock()
        => _host.Run(() =>
        {
            var window = new InstallWindow("", "https://api.test");

            Assert.True(IsSealed(window));
        });

    /// <summary>
    /// שדרוג: אין אסימון, ואין חסימה.
    ///
    /// זו הבדיקה שכל השאר קיימות בשבילה. בלעדיה כל עדכון אוטומטי
    /// היה חוסם את המחשב שהוא בא לעדכן.
    /// </summary>
    [Fact]
    public void UpgradeIsNotATotalBlock()
        => _host.Run(() =>
        {
            var window = new InstallWindow("", "https://api.test", upgrade: true);

            Assert.False(IsSealed(window));
        });

    /// <summary>
    /// זיהוי מחשב רשום אינו זורק גם כשאין הרשאה לקרוא את התיקייה.
    ///
    /// היא מוגנת ב-ACL, והמתקין רץ לפני ההסלמה. חריגה כאן הייתה
    /// מפילה את ההתקנה כולה.
    /// </summary>
    [Fact]
    public void EnrolmentCheckNeverThrows()
    {
        var exception = Record.Exception(() => InstallEngine.IsAlreadyEnrolled());

        Assert.Null(exception);
    }

    private static bool IsSealed(InstallWindow window)
    {
        var field = typeof(InstallWindow).GetField(
            "_sealed",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);

        return (bool)field!.GetValue(window)!;
    }
}
