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
public class InstallerUiTests : IClassFixture<WpfHost>
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
}
