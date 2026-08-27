using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace SafeMe.Installer;

/// <summary>
/// מתקין SafeMe.
///
/// הרעיון שמאחורי כל התהליך: הקובץ שהמשתמש הוריד נקרא
/// SafeMe-Setup-ENR-XXXX.exe, והאסימון שבשמו הוא שמקשר את המחשב
/// לחשבון. אין מה להקליד ואין מה להעתיק.
///
/// שני מסלולים, ואותו מנוע לשניהם:
///
/// בלי דגלים נפתח חלון. זה מה שהורה רואה, וזה מה שצריך להיראות
/// כמו תוכנה ולא כמו מסך שחור שנפתח לרגע.
///
/// עם ‎--quiet יש פלט טקסט בלבד, לפריסה מרוכזת ולבדיקות. שני
/// המסלולים מריצים את InstallEngine, ולכן אין מצב שאחד מהם מתקין
/// משהו קצת אחר.
/// </summary>
[SupportedOSPlatform("windows")]
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var quiet = args.Contains("--quiet") || args.Contains("--silent");

        return quiet ? RunConsole(args) : RunGui(args);
    }

    // ---------------------------------------------------------------- גרפי

    private static int RunGui(string[] args)
    {
        var app = new App(args);

        app.InitializeComponent();

        return app.Run();
    }

    // ---------------------------------------------------------------- שקט

    /*
     * הקובץ נבנה כ-WinExe, ולכן אין לו מסוף משלו — וזה בדיוק מה
     * שמונע את המסך השחור. במצב שקט הוא מתחבר למסוף של מי שהריץ
     * אותו, אם יש כזה. כשאין (הרצה ממשימה מתוזמנת, למשל) הכתיבה
     * פשוט נבלעת, וזה המצב הרצוי.
     */

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int processId);

    private const int AttachParentProcess = -1;

    private static int RunConsole(string[] args)
    {
        AttachConsole(AttachParentProcess);

        try
        {
            Console.OutputEncoding = Encoding.UTF8;
        }
        catch (IOException)
        {
            // אין מסוף מחובר. הפלט ייבלע, וזה תקין.
        }

        var token = InstallEngine.FindToken(args);

        if (token is null)
        {
            Write("✗ לא נמצא קוד התקנה.");
            Write("  שם הקובץ אמור להיות SafeMe-Setup-ENR-XXXXXXXXXXXXXXXXXXXXXXXX.exe,");
            Write("  או שיש להעביר ‎--token ENR-...");

            return 2;
        }

        var server = InstallEngine.FindServer(args);

        Write($"SafeMe · חשבון {InstallEngine.Mask(token)} · {server}");

        var progress = new Progress<InstallProgress>(p => Write($"  · {p.Message}"));
        var engine = new InstallEngine(progress);

        try
        {
            var result = engine.RunAsync(token, server).GetAwaiter().GetResult();

            Write(result.Succeeded ? $"✓ {result.Message}" : $"✗ {result.Message}");

            return result.ExitCode;
        }
        catch (Exception ex)
        {
            Write($"✗ {ex.Message}");
            return 1;
        }
    }

    private static void Write(string text)
    {
        try { Console.WriteLine(text); }
        catch (IOException) { /* אין מסוף. */ }
    }
}
