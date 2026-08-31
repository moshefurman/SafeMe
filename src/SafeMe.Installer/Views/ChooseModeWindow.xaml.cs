using System.Runtime.Versioning;
using System.Windows;

using SafeMe.Core.Security;

namespace SafeMe.Installer.Views;

/// <summary>מה המשתמש בחר במסך שאין בו קוד.</summary>
public enum ChosenMode
{
    Cancelled,

    /// <summary>קוד הוקלד. התקנה רגילה, מקושרת לחשבון.</summary>
    Enroll,

    /// <summary>חסימה מוחלטת בלי חשבון.</summary>
    Seal
}

/// <summary>
/// המסך שמוצג כשאין קוד התקנה.
///
/// שתי האפשרויות אינן שקולות, והמסך לא מתיימר שכן. הזנת הקוד היא
/// המסלול הרגיל ולכן היא למעלה, עם הכפתור הראשי. החסימה המוחלטת
/// היא מסלול חד-כיווני, ולכן היא בתיבה אדומה, דורשת סימון מפורש,
/// ואומרת במפורש שההסרה בתשלום.
///
/// אין כאן "האם אתה בטוח" נוסף אחרי הלחיצה. תיבת אישור שמופיעה
/// אחרי שכבר סימנת וכבר לחצת היא הרגל של ללחוץ "כן" בלי לקרוא, וזה
/// בדיוק מה שהופך אזהרה למיותרת.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class ChooseModeWindow : Window
{
    public ChosenMode Mode { get; private set; } = ChosenMode.Cancelled;

    /// <summary>הקוד שהוקלד, כשנבחרה התקנה רגילה.</summary>
    public string Token { get; private set; } = "";

    /// <summary>
    /// מה נבחר לגבי אופן ההסרה: self_service או support_only.
    ///
    /// ריק במסלול החסימה המוחלטת — שם אין חשבון, ולכן אין הגדרה
    /// של דייר שאפשר לקבוע.
    /// </summary>
    public string UninstallPolicy { get; private set; } = "";

    public ChooseModeWindow() => InitializeComponent();

    // ---------------------------------------------------------------- קוד

    /// <summary>
    /// בדיקת הקוד תוך כדי הקלדה.
    ///
    /// הבדיקה היא מבנית בלבד — היא מוודאת שהצורה נכונה, לא שהקוד
    /// קיים. אימות אמיתי דורש את השרת, וההודעה נזהרת לא להבטיח
    /// יותר ממה שהיא יודעת.
    /// </summary>
    private void OnTokenChanged(object sender, RoutedEventArgs e)
    {
        var raw = TokenBox.Text.Trim();

        if (raw.Length == 0)
        {
            EnrollButton.IsEnabled = false;
            TokenHint.Text = "ההתקנה תקשר את המחשב לחשבון, ותוכל לנהל אותו מרחוק.";

            return;
        }

        // המשתמש מדביק לעיתים את שם הקובץ כולו, או כתובת מהאתר.
        // חילוץ מנוסח כזה עדיף על הודעת שגיאה שנכונה טכנית וחסרת
        // תועלת מעשית.
        var token = InstallerToken.IsWellFormed(raw)
            ? raw
            : InstallerToken.FromFileName(raw);

        var valid = token is not null && InstallerToken.IsWellFormed(token);

        EnrollButton.IsEnabled = valid;
        Token = valid ? token!.ToUpperInvariant() : "";

        TokenHint.Text = valid
            ? "הקוד בנוי כשורה. הקישור לחשבון ייבדק מול השרת בזמן ההתקנה."
            : "הקוד אינו בנוי כשורה. הוא מתחיל ב-ENR ואחריו 24 תווים.";
    }

    private void OnEnrollClick(object sender, RoutedEventArgs e)
    {
        UninstallPolicy = SupportOnlyOption.IsChecked == true ? "support_only" : "self_service";
        Mode = ChosenMode.Enroll;
        DialogResult = true;
    }

    // ---------------------------------------------------------------- חסימה

    private void OnSealConfirmChanged(object sender, RoutedEventArgs e)
        => SealButton.IsEnabled = SealConfirm.IsChecked == true;

    private void OnSealClick(object sender, RoutedEventArgs e)
    {
        // הגנה כפולה. הכפתור מושבת בלי הסימון, וגם אם משהו בממשק
        // ישתבש — פעולה שאין ממנה חזרה לא תתחיל בלי אישור מפורש.
        if (SealConfirm.IsChecked != true) return;

        Mode = ChosenMode.Seal;
        DialogResult = true;
    }

    private void OnCancelClick(object sender, RoutedEventArgs e) => DialogResult = false;
}
