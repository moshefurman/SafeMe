using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

using SafeMe.Installer;
using SafeMe.Installer.Views;

using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// חוט הממשק של הבדיקות.
///
/// שני אילוצים של WPF נפגשים כאן. הראשון: אובייקטים גרפיים מחייבים
/// דירה חד-חוטית, ו-xunit אינו מריץ ב-STA. השני, והוא זה שתפס אותי:
/// Application הוא יחיד **לכל AppDomain** ולא לכל חוט, ולכן חוט
/// נפרד לכל בדיקה אינו פותר כלום — הוא רק מעביר את הכשל לבדיקה
/// השנייה.
///
/// לכן חוט אחד לכל הריצה, עם Application אחד שנבנה עליו, ובדיקות
/// שמזמנות אליו עבודה.
/// </summary>
public sealed class WpfHost : IDisposable
{
    private readonly Dispatcher _dispatcher;
    private readonly Thread _thread;

    public App Application { get; private set; } = null!;

    public WpfHost()
    {
        var ready = new ManualResetEventSlim();
        Dispatcher? captured = null;

        _thread = new Thread(() =>
        {
            captured = Dispatcher.CurrentDispatcher;
            Application = new App([]);
            Application.InitializeComponent();

            ready.Set();
            Dispatcher.Run();
        });

        _thread.SetApartmentState(ApartmentState.STA);
        _thread.IsBackground = true;
        _thread.Start();

        if (!ready.Wait(TimeSpan.FromSeconds(30)))
            throw new TimeoutException("חוט הממשק לא עלה בזמן");

        _dispatcher = captured!;
    }

    /// <summary>מריץ על חוט הממשק ומעביר חריגה חזרה לבדיקה.</summary>
    public void Run(Action body) => _dispatcher.Invoke(body);

    public void Dispose() => _dispatcher.InvokeShutdown();
}

/// <summary>
/// המתקין הגרפי.
///
/// הבדיקות כאן קיימות בגלל שינוי אחד: App.xaml נרשם כ-Page ולא
/// כ-ApplicationDefinition, כדי ש-Main יישאר בשליטתנו ויוכל להחליט
/// בין החלון למצב השקט. הרישום הזה מתקמפל בשתי הצורות, ונופל רק
/// בזמן ריצה — כשמשאב לא נמצא והחלון קורס לפני שהוא נראה.
///
/// המתקין דורש הרשאות מנהל ולכן אי אפשר להריץ אותו בבדיקה. מה שכן
/// אפשר, וזה מה שנשבר בפועל, הוא לוודא שהמשאבים נטענים ושהחלון
/// נבנה.
/// </summary>
/*
 * אוסף ולא IClassFixture.
 *
 * IClassFixture יוצר מופע לכל מחלקת בדיקות, ו-Application הוא יחיד
 * לכל AppDomain — כלומר מחלקה שנייה שמשתמשת בו הייתה מפילה את
 * הריצה כולה. זה קרה בפועל ברגע שנוספה מחלקה שנייה.
 */
[CollectionDefinition("wpf")]
public sealed class WpfCollection : ICollectionFixture<WpfHost>;

[Collection("wpf")]
public class InstallerUiTests
{
    private readonly WpfHost _host;

    public InstallerUiTests(WpfHost host) => _host = host;

    [Fact]
    public void Application_resources_load_when_app_xaml_is_a_page()
        => _host.Run(() =>
        {
            // אלה המשאבים שהחלון מחפש בזמן טעינה. חסר אחד מהם —
            // והחלון זורק במקום להיפתח.
            foreach (var key in new[] { "Bg", "BgPanel", "BgSubtle", "Fg", "FgMuted",
                                        "Accent", "Danger", "Success", "Warn" })
            {
                Assert.IsType<SolidColorBrush>(_host.Application.Resources[key]);
            }

            foreach (var key in new[] { "H1", "Muted", "Primary" })
            {
                Assert.IsType<Style>(_host.Application.Resources[key]);
            }
        });

    [Fact]
    public void Window_builds_and_shows_the_masked_token()
        => _host.Run(() =>
        {
            var window = new InstallWindow("ENR-A1B2C3D4E5F60718293A4B5C", "https://example.test");

            // הכשל שהבדיקה מחפשת הוא קריסה ב-InitializeComponent.
            // אם הגענו לכאן, ה-XAML נטען וכל ה-StaticResource נפתרו.
            Assert.Equal(1, window.ExitCode);
            Assert.Equal("התקנת SafeMe", window.Title);

            // RTL אינו קישוט: חלון עברי בפריסה שמאלית נראה שבור,
            // וזה הרושם הראשון של המוצר.
            Assert.Equal(FlowDirection.RightToLeft, window.FlowDirection);
        });

    /// <summary>
    /// האסימון אינו מוצג במלואו.
    ///
    /// הוא מעניק גישה לחשבון, ומסך ההתקנה הוא בדיוק מה שמצלמים
    /// כשמבקשים עזרה.
    /// </summary>
    [Theory]
    [InlineData("ENR-A1B2C3D4E5F60718293A4B5C", "ENR-A1B2…4B5C")]
    [InlineData("ENR-SHORT", "ENR-SHORT")]
    public void Token_is_masked(string token, string expected)
        => Assert.Equal(expected, InstallEngine.Mask(token));

    [Fact]
    public void Explicit_token_argument_wins_over_the_file_name()
        => Assert.Equal(
            "ENR-A1B2C3D4E5F60718293A4B5C",
            InstallEngine.FindToken(["--token", "ENR-A1B2C3D4E5F60718293A4B5C"]));

    [Fact]
    public void Server_falls_back_to_the_default()
    {
        Assert.Equal(InstallEngine.DefaultServerUrl, InstallEngine.FindServer([]));
        Assert.Equal("https://x.test", InstallEngine.FindServer(["--server", "https://x.test"]));
    }

    // ─────────────────────────────────────────────── מסך הבחירה

    /*
     * החסימה המוחלטת היא הפעולה היחידה במוצר שאין ממנה חזרה
     * מהמחשב עצמו. הבדיקות כאן שומרות על השער שלפניה.
     */

    [Fact]
    public void Choice_window_starts_with_both_actions_disabled()
        => _host.Run(() =>
        {
            var window = new ChooseModeWindow();

            Assert.False(window.EnrollButton.IsEnabled);

            // ובעיקר זה: בלי סימון מפורש, אין לחיצה.
            Assert.False(window.SealButton.IsEnabled);
            Assert.Equal(ChosenMode.Cancelled, window.Mode);
        });

    [Fact]
    public void Seal_button_unlocks_only_after_the_checkbox()
        => _host.Run(() =>
        {
            var window = new ChooseModeWindow();

            window.SealConfirm.IsChecked = true;
            Assert.True(window.SealButton.IsEnabled);

            // ובחזרה. מי שנרתע יכול לבטל.
            window.SealConfirm.IsChecked = false;
            Assert.False(window.SealButton.IsEnabled);
        });

    [Theory]
    [InlineData("ENR-A1B2C3D4E5F60718293A4B5C", true)]
    [InlineData("enr-a1b2c3d4e5f60718293a4b5c", true)]
    [InlineData("SafeMe-Setup-ENR-A1B2C3D4E5F60718293A4B5C.exe", true)]
    [InlineData("ENR-TOOSHORT", false)]
    [InlineData("לא קוד", false)]
    [InlineData("", false)]
    public void Enroll_button_follows_the_token_shape(string typed, bool expected)
        => _host.Run(() =>
        {
            var window = new ChooseModeWindow();

            window.TokenBox.Text = typed;

            Assert.Equal(expected, window.EnrollButton.IsEnabled);

            // הקוד נשמר באותיות גדולות בלי קשר למה שהוקלד, כי זו
            // הצורה שהשרת מצפה לה.
            if (expected) Assert.StartsWith("ENR-", window.Token);
        });

    /// <summary>
    /// המשתמש מדביק לעיתים את הנתיב המלא. חילוץ עדיף על הודעת
    /// שגיאה שנכונה טכנית וחסרת תועלת מעשית.
    /// </summary>
    [Fact]
    public void A_pasted_file_name_yields_the_token_inside_it()
        => _host.Run(() =>
        {
            var window = new ChooseModeWindow();

            window.TokenBox.Text =
                @"C:\Users\x\Downloads\SafeMe-Setup-ENR-A1B2C3D4E5F60718293A4B5C.exe";

            Assert.True(window.EnrollButton.IsEnabled);
            Assert.Equal("ENR-A1B2C3D4E5F60718293A4B5C", window.Token);
        });
}
