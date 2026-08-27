using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Media;

namespace SafeMe.Installer.Views;

/// <summary>
/// חלון ההתקנה.
///
/// שלושה מצבים באותו חלון ולא אשף רב-עמודים: הסבר, התקדמות, תוצאה.
/// למשתמש אין כאן החלטות לקבל — האסימון כבר בשם הקובץ, ואין מה
/// לבחור — ולכן אשף היה ארבע לחיצות "הבא" בלי תוכן.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class InstallWindow : Window
{
    private readonly string _token;
    private readonly string _server;
    private readonly ObservableCollection<StepRow> _steps = [];

    private bool _running;
    private bool _finished;

    public int ExitCode { get; private set; } = 1;

    public InstallWindow(string token, string server)
    {
        InitializeComponent();

        _token = token;
        _server = server;

        AccountText.Text = InstallEngine.Mask(token);
        ServerText.Text = server;

        StepList.ItemsSource = _steps;
    }

    // ---------------------------------------------------------------- פעולות

    private async void OnPrimaryClick(object sender, RoutedEventArgs e)
    {
        if (_finished)
        {
            Close();
            return;
        }

        if (_running) return;

        _running = true;

        IntroPanel.Visibility = Visibility.Collapsed;
        ProgressPanel.Visibility = Visibility.Visible;

        PrimaryButton.IsEnabled = false;
        PrimaryButton.Content = "מתקין...";

        // הסגירה נחסמת בזמן ההתקנה: חצי התקנה גרועה מאין התקנה,
        // והיא המצב שקשה ביותר לתקן מרחוק.
        CloseButton.IsEnabled = false;

        _steps.Clear();

        AddStep(InstallStage.Runtime, "סביבת הרצה");
        AddStep(InstallStage.Payload, "פריסת קבצים");
        AddStep(InstallStage.Install, "התקנת השירות והרישום");

        var progress = new Progress<InstallProgress>(OnProgress);
        var engine = new InstallEngine(progress);

        InstallResult result;

        try
        {
            result = await engine.RunAsync(_token, _server);
        }
        catch (Exception ex)
        {
            result = new InstallResult(1, ex.Message);
        }

        Finish(result);
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    /// <summary>
    /// מונע סגירה באמצע.
    ///
    /// גם כפתור ה-X, לא רק "ביטול": חצי התקנה משאירה שירות רשום
    /// בלי קבצים, וזה בדיוק המצב שאין ממנו דרך חזרה בלי ידיים.
    /// </summary>
    protected override void OnClosing(CancelEventArgs e)
    {
        if (_running && !_finished) e.Cancel = true;

        base.OnClosing(e);
    }

    // ---------------------------------------------------------------- התקדמות

    private void OnProgress(InstallProgress progress)
    {
        var row = _steps.FirstOrDefault(s => s.Stage == progress.Stage);

        if (row is null) return;

        // כל שלב שהתחיל מסמן את הקודמים כגמורים. השרשור הזה חוסך
        // דיווח "סיימתי" נפרד לכל שלב, שהיה מכפיל את נקודות הדיווח
        // ואת ההזדמנויות לשכוח אחת מהן.
        foreach (var earlier in _steps.TakeWhile(s => s.Stage != progress.Stage))
            earlier.MarkDone();

        row.MarkActive(progress.Message);

        if (progress.Fraction is { } fraction)
        {
            Bar.IsIndeterminate = false;
            Bar.Value = fraction * 100;
        }
        else
        {
            Bar.IsIndeterminate = true;
        }
    }

    private void AddStep(InstallStage stage, string title) => _steps.Add(new StepRow(stage, title));

    // ---------------------------------------------------------------- סיום

    private void Finish(InstallResult result)
    {
        _finished = true;
        _running = false;
        ExitCode = result.ExitCode;

        ProgressPanel.Visibility = Visibility.Collapsed;
        ResultPanel.Visibility = Visibility.Visible;

        CloseButton.Visibility = Visibility.Collapsed;
        PrimaryButton.IsEnabled = true;
        PrimaryButton.Content = "סגור";

        if (result.Succeeded)
        {
            ResultTitle.Text = "ההתקנה הושלמה";
            ResultTitle.Foreground = (Brush)FindResource("Success");

            ResultBody.Text =
                "תג המצב יופיע בפינת המסך תוך כמה שניות, והמחשב יופיע במרכז הניהול שלך.";

            ResultHint.Visibility = Visibility.Visible;
            ResultHintText.Text =
                "שתי המלצות שסוגרות את מה שהתוכנה אינה יכולה לסגור בעצמה: " +
                "הגדר סיסמה ל-BIOS ובטל אתחול מהתקן חיצוני, " +
                "וּודא שחשבון הילד אינו חשבון מנהל.";

            return;
        }

        ResultTitle.Text = "ההתקנה נכשלה";
        ResultTitle.Foreground = (Brush)FindResource("Danger");
        ResultBody.Text = result.Message;

        ResultHint.Visibility = Visibility.Visible;
        ResultHintText.Text = result.ExitCode == 3
            ? "אפשר להתקין את סביבת ההרצה ידנית ואז להריץ שוב את המתקין:\n"
              + InstallEngine.RuntimeDownloadPage
            : "לא בוצע שינוי קבוע במחשב. אפשר להריץ את המתקין שוב.";
    }

    // ---------------------------------------------------------------- שורה

    /// <summary>
    /// שורת שלב בתצוגה.
    ///
    /// מממשת INotifyPropertyChanged ידנית ולא דרך ספרייה: שלוש
    /// תכונות משתנות, ותלות נוספת במתקין היא תלות שצריך גם לארוז.
    /// </summary>
    private sealed class StepRow : INotifyPropertyChanged
    {
        private static readonly Brush Idle = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x95, 0xA1, 0xB2));
        private static readonly Brush Active = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3B, 0x82, 0xF6));
        private static readonly Brush Done = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x22, 0xC5, 0x5E));
        private static readonly Brush Text = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0xED, 0xF1, 0xF7));

        private string _glyph = "○";
        private string _detail = "";
        private Brush _color = Idle;
        private Brush _titleColor = Idle;

        public StepRow(InstallStage stage, string title)
        {
            Stage = stage;
            Title = title;
        }

        public InstallStage Stage { get; }
        public string Title { get; }

        public string Glyph { get => _glyph; private set => Set(ref _glyph, value); }
        public string Detail { get => _detail; private set => Set(ref _detail, value); }
        public Brush Color { get => _color; private set => Set(ref _color, value); }
        public Brush TitleColor { get => _titleColor; private set => Set(ref _titleColor, value); }

        public Visibility DetailVisibility =>
            string.IsNullOrEmpty(_detail) ? Visibility.Collapsed : Visibility.Visible;

        public void MarkActive(string detail)
        {
            Glyph = "◉";
            Color = Active;
            TitleColor = Text;
            Detail = detail;

            Raise(nameof(DetailVisibility));
        }

        public void MarkDone()
        {
            // שלב שכבר סומן כגמור אינו חוזר להיות פעיל
            if (Glyph == "✓") return;

            Glyph = "✓";
            Color = Done;
            TitleColor = Text;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void Set<T>(ref T field, T value, [System.Runtime.CompilerServices.CallerMemberName] string? name = null)
        {
            if (Equals(field, value)) return;

            field = value;
            Raise(name);
        }

        private void Raise(string? name)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
