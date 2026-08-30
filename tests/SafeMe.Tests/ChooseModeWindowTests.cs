using SafeMe.Installer.Views;

namespace SafeMe.Tests;

/// <summary>
/// חלון בחירת מצב ההתקנה.
///
/// נכתב אחרי דיווח מהשטח: "מכניס את האסימון ידנית וההתקנה קורסת".
/// זהו החלון היחיד במתקין שנפתח רק כשאין אסימון בשם הקובץ — כלומר
/// רק כשמישהו הוריד את המתקין ישירות — ולכן הוא גם החלון היחיד
/// שלא נבדק אף פעם במסלול הרגיל.
/// </summary>
[Collection("wpf")]
public sealed class ChooseModeWindowTests
{
    private readonly WpfHost _host;

    public ChooseModeWindowTests(WpfHost host) => _host = host;

    /// <summary>
    /// עצם הבנייה. XAML שמפנה לאירוע עם חתימה שאינה תואמת נכשל
    /// בטעינה ולא בקומפילציה — כלומר החלון נבנה, נארז, ונופל רק
    /// אצל המשתמש.
    /// </summary>
    [Fact]
    public void ItLoads()
        => _host.Run(() =>
        {
            var exception = Record.Exception(() => new ChooseModeWindow());

            Assert.Null(exception);
        });

    /// <summary>הקלדת קוד תקין מפעילה את הכפתור ושומרת אותו.</summary>
    [Fact]
    public void AcceptsATypedToken()
        => _host.Run(() =>
        {
            var window = new ChooseModeWindow();

            window.TokenBox.Text = "ENR-0123456789ABCDEF01234567";

            Assert.Equal("ENR-0123456789ABCDEF01234567", window.Token);
        });

    /// <summary>קוד משובש אינו מתקבל, והכפתור נשאר מושבת.</summary>
    [Fact]
    public void RejectsRubbish()
        => _host.Run(() =>
        {
            var window = new ChooseModeWindow();

            window.TokenBox.Text = "לא קוד";

            Assert.Equal("", window.Token);
        });

    /// <summary>
    /// שם קובץ מלא מתקבל גם הוא.
    ///
    /// המשתמש מדביק לעיתים את שם הקובץ שהוריד במקום את הקוד עצמו,
    /// והודעת שגיאה שנכונה טכנית לא הייתה עוזרת לו.
    /// </summary>
    [Fact]
    public void ExtractsFromAPastedFileName()
        => _host.Run(() =>
        {
            var window = new ChooseModeWindow();

            window.TokenBox.Text = "SafeMe-Setup-ENR-0123456789ABCDEF01234567.exe";

            Assert.Equal("ENR-0123456789ABCDEF01234567", window.Token);
        });
}
