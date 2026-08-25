using System.Windows;
using System.Windows.Media;
using SafeMe.Core.Ipc;

namespace SafeMe.Uninstaller.Views;

/// <summary>
/// מסך ההסרה. חשוב להבין את גבולות האחריות שלו: המסך אינו מאמת דבר.
/// הוא מציג אתגר שהופק על ידי השירות, ומעביר את הקוד שהמשתמש הקליד
/// לאימות בתוך השירות שרץ כ-SYSTEM. החלפת המסך אינה מקנה שום יתרון לתוקף.
/// </summary>
public partial class UninstallWindow : Window
{
    private readonly IpcClient _client = new();

    private string? _challenge;
    private DateTimeOffset? _expiresUtc;

    public UninstallWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!await _client.IsServiceAliveAsync())
        {
            ShowMessage(
                "שירות SafeMe אינו פעיל. יש להפעילו לפני ההסרה. " +
                "אם השירות אינו עולה, פנו לתמיכה.",
                isError: true);

            GenerateButton.IsEnabled = false;

            return;
        }

        await RefreshLockoutStateAsync();
    }

    // ------------------------------------------------------------ שלב 1

    private async void OnGenerateClick(object sender, RoutedEventArgs e)
    {
        GenerateButton.IsEnabled = false;
        HideMessage();

        try
        {
            var result = await _client.SendAsync<UninstallChallengeResult>(
                IpcOps.UninstallChallenge, new UninstallChallengePayload { Reason = "בקשת משתמש" });

            if (result is null)
            {
                ShowMessage("לא התקבלה תשובה מהשירות.", isError: true);
                return;
            }

            _challenge = result.Challenge;
            _expiresUtc = result.ExpiresUtc;

            ChallengeBox.Text = result.Challenge;
            CopyButton.IsEnabled = true;
            ExpiryText.Text = $"בתוקף עד {result.ExpiresUtc.ToLocalTime():HH:mm}";

            ModeHint.Text = result.Mode.Equals("Rsa", StringComparison.OrdinalIgnoreCase)
                ? "קוד ההסרה ארוך. הדביקו אותו במלואו בשדה למעלה."
                : "קוד ההסרה הוא 24 תווים בארבע קבוצות. ניתן להקליד עם או בלי מקפים.";

            UpdateVerifyButton();
        }
        catch (Exception ex)
        {
            // הודעת השירות כבר מנוסחת בעברית וכוללת את סיבת הדחייה
            ShowMessage(ex.Message, isError: true);
        }
        finally
        {
            GenerateButton.IsEnabled = true;
        }
    }

    private void OnCopyClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_challenge)) return;

        try
        {
            Clipboard.SetText(_challenge);
            ShowMessage("קוד האתגר הועתק.", isError: false);
        }
        catch (Exception)
        {
            // לוח ההעתקה עלול להיות נעול על ידי יישום אחר
            ShowMessage("לא ניתן להעתיק. סמנו את הקוד והעתיקו ידנית.", isError: true);
        }
    }

    // ------------------------------------------------------------ שלב 2

    private void OnResponseChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        UpdateVerifyButton();

    private void UpdateVerifyButton() =>
        VerifyButton.IsEnabled =
            !string.IsNullOrWhiteSpace(_challenge) &&
            ResponseBox.Text.Trim().Length >= 8;

    private async void OnVerifyClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_challenge)) return;

        VerifyButton.IsEnabled = false;
        HideMessage();

        try
        {
            var result = await _client.SendAsync<UninstallVerifyResult>(
                IpcOps.UninstallVerify,
                new UninstallVerifyPayload
                {
                    Challenge = _challenge,
                    Response = ResponseBox.Text.Trim()
                });

            if (result is null)
            {
                ShowMessage("לא התקבלה תשובה מהשירות.", isError: true);
                return;
            }

            if (result.Granted)
            {
                ShowMessage(result.Message + "\nניתן לסגור חלון זה ולהמשיך בהסרה מלוח הבקרה.", isError: false);

                ResponseBox.IsEnabled = false;
                GenerateButton.IsEnabled = false;
                AttemptsText.Text = "";

                return;
            }

            ShowMessage(result.Message, isError: true);

            AttemptsText.Text = result.LockoutUntil is { } until
                ? $"נעול עד {until.ToLocalTime():HH:mm}"
                : $"נותרו {result.AttemptsLeft} ניסיונות";

            if (result.LockoutUntil is not null)
            {
                ResponseBox.IsEnabled = false;
                GenerateButton.IsEnabled = false;
            }
        }
        catch (Exception ex)
        {
            ShowMessage(ex.Message, isError: true);
        }
        finally
        {
            UpdateVerifyButton();
        }
    }

    private void OnCancelClick(object sender, RoutedEventArgs e) => Close();

    // ------------------------------------------------------------ עזר

    private async Task RefreshLockoutStateAsync()
    {
        try
        {
            var state = await _client.SendAsync<LockoutStateResult>(IpcOps.LockoutState);

            if (state is { Active: true, Until: { } until })
            {
                ShowMessage(
                    $"{state.Reason ?? "המכשיר נעול"}. ניתן יהיה לנסות שוב ב-{until.ToLocalTime():HH:mm}.",
                    isError: true);

                GenerateButton.IsEnabled = false;
            }
        }
        catch (Exception)
        {
            // אין מצב נעילה לדווח עליו
        }
    }

    private void ShowMessage(string text, bool isError)
    {
        MessageText.Text = text;

        MessageText.Foreground = isError
            ? (Brush)FindResource("Danger")
            : (Brush)FindResource("Success");

        MessageBorder.Visibility = Visibility.Visible;
    }

    private void HideMessage() => MessageBorder.Visibility = Visibility.Collapsed;
}
