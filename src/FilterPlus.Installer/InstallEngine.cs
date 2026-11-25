using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.Versioning;

using FilterPlus.Core.Security;

namespace FilterPlus.Installer;

/// <summary>שלבי ההתקנה, לפי הסדר. משמש לסימון התקדמות בממשק.</summary>
public enum InstallStage
{
    Account,
    Runtime,
    Payload,
    Install,
    Done
}

/// <summary>דיווח התקדמות יחיד.</summary>
public sealed record InstallProgress(
    InstallStage Stage,
    string Message,
    bool IsError = false)
{
    /// <summary>0 עד 1 בתוך השלב, או null כשאין מידה.</summary>
    public double? Fraction { get; init; }
}

/// <summary>תוצאת ההתקנה.</summary>
public sealed record InstallResult(int ExitCode, string Message)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// ההתקנה עצמה, בלי ממשק.
///
/// הופרדה מהתצוגה כדי ששני המסלולים — החלון והמצב השקט — יריצו
/// בדיוק את אותו קוד. מתקין גרפי שמבצע צעדים מעט אחרים מהשקט הוא
/// שני מתקינים, ורק אחד מהם נבדק.
///
/// ההתקנה עצמה אינה מיושמת כאן אלא ב-install.ps1 שנפרס ומורץ.
/// הסקריפט כבר מטפל בהקשחת הרשאות, ברישום ל-Safe Mode, ובמשימת
/// הגיבוי; שכפול ההיגיון הזה ב-C# היה יוצר שני מקורות אמת.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class InstallEngine
{
    /// <summary>כתובת השרת. ניתנת לעקיפה בשורת הפקודה לצורכי בדיקה.</summary>
    /*
     * דומיין משלנו, ולא כתובת של ספק האירוח.
     *
     * הכתובת הזו נכתבת לתוך appsettings של כל התקנה ונשארת שם.
     * כל עוד היא של Render, החלפת אירוח מחייבת לגעת בכל מחשב —
     * ועם אלפי התקנות זו החלטה שאי אפשר לחזור ממנה.
     *
     * מחשבים קיימים אינם מושפעים: כל אחד ממשיך לדבר עם מה שנכתב
     * לו בהתקנה, ומתיר את זה לעצמו אוטומטית. מה שמשתנה הוא רק
     * מה שנולד מכאן והלאה.
     */
    public const string DefaultServerUrl = "https://api.filterplus.co.il";

    /// <summary>
    /// כתובת מרכז הניהול.
    ///
    /// מארח נפרד מה-API, ולכן היא נמסרת בנפרד. זה אינו פרט טכני:
    /// בלעדיה, מחשב שנחסם אינו יכול להגיע למסך שבו מסירים את
    /// החסימה — וההורה נשאר מול מחשב נעול בלי דרך פנימה.
    /// </summary>
    public const string DefaultPortalUrl = "https://www.filterplus.co.il";

    private const string RequiredRuntime = "Microsoft.WindowsDesktop.App";
    private const int RequiredMajor = 9;

    /// <summary>המפנה הרשמי לגרסה היציבה האחרונה בענף 9.</summary>
    private const string RuntimeInstallerUrl =
        "https://aka.ms/dotnet/9.0/windowsdesktop-runtime-win-x64.exe";

    public const string RuntimeDownloadPage =
        "https://dotnet.microsoft.com/download/dotnet/9.0/runtime";

    private readonly IProgress<InstallProgress> _progress;

    /// <summary>כתובת הפורטל שתיכתב לתצורה. נקבעת בבנייה.</summary>
    public string PortalUrl { get; init; } = DefaultPortalUrl;

    public InstallEngine(IProgress<InstallProgress> progress) => _progress = progress;

    /// <summary>האסימון שנמצא, אם נמצא. null פירושו שאין מה להתקין.</summary>
    public static string? FindToken(string[] args)
        => ArgValue(args, "--token") ?? InstallerToken.FromFileName(Environment.ProcessPath);

    /// <summary>
    /// האם המחשב כבר רשום לחשבון.
    ///
    /// זו ההבחנה שהייתה חסרה, והיא עצרה את העדכון האוטומטי: אסימון
    /// נדרש לרישום ראשון בלבד. שדרוג על מחשב שכבר רשום אינו צריך
    /// אותו — הזהות שלו יושבת בקובץ המצב, וההתקנה אינה נוגעת בו.
    ///
    /// בלי ההבחנה, המתקין דרש קוד גם בשדרוג. במסך זה מעצבן; במסלול
    /// ‎--quiet, שהוא בדיוק זה שהעדכון האוטומטי מריץ, זה היה יציאה
    /// עם קוד 2 — כלומר עדכון שלא קרה, בשקט, לנצח.
    ///
    /// הקובץ מוצפן ומוגן ב-ACL, ולכן עצם קיומו הוא הסימן. תוכנו
    /// אינו נקרא כאן: המתקין אינו צריך לדעת מי המחשב, רק שהוא כבר
    /// מוכר.
    /// </summary>
    public static bool IsAlreadyEnrolled()
    {
        try
        {
            return File.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FilterPlus", "state", "device.dat"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            /*
             * ספק מוכרע לטובת "לא רשום".
             *
             * טעות לכיוון הזה מבקשת קוד מיותר; טעות לכיוון השני
             * מתקינה בלי רישום ומשאירה מחשב שאינו שייך לאף חשבון.
             */
            return false;
        }
    }

    public static string FindServer(string[] args)
        => ArgValue(args, "--server") ?? DefaultServerUrl;

    public static string FindPortal(string[] args)
        => ArgValue(args, "--portal") ?? DefaultPortalUrl;

    /// <summary>
    /// מסתיר את רוב האסימון בתצוגה. הוא מעניק גישה לחשבון, ואין
    /// סיבה שיישאר בצילום מסך או בהקלטת תמיכה.
    /// </summary>
    public static string Mask(string token)
        => token.Length <= 10 ? token : $"{token[..8]}…{token[^4..]}";

    /// <summary>
    /// מריץ את ההתקנה במלואה.
    ///
    /// שלושה מצבים, ולא שניים — וההבחנה ביניהם קריטית:
    ///
    ///   אסימון      רישום חדש לחשבון.
    ///   ריק         התקנה ללא חשבון: המחשב נחסם לחלוטין, וההסרה
    ///               מחייבת קוד מהמוקד. רק אחרי אישור מפורש.
    ///   שדרוג       מחשב שכבר רשום. אין רישום ואין חסימה.
    ///
    /// איחוד השניים האחרונים היה הופך כל שדרוג לחסימה מוחלטת של
    /// מחשב שהיה מנוהל כהלכה — כולל כל עדכון אוטומטי.
    /// </summary>
    public async Task<InstallResult> RunAsync(
        string token,
        string serverUrl,
        bool upgrade = false,
        string? uninstallPolicy = null,
        string? networkFloor = null,
        CancellationToken ct = default)
    {
        var unmanaged = !upgrade && string.IsNullOrWhiteSpace(token);

        Report(InstallStage.Account, upgrade
            ? "שדרוג — המחשב כבר רשום"
            : unmanaged
                ? "ללא חשבון — חסימה מוחלטת"
                : $"חשבון {Mask(token)}");

        // ---- סביבת ההרצה ----

        if (RuntimeInstalled())
        {
            Report(InstallStage.Runtime, "סביבת ההרצה קיימת.");
        }
        else
        {
            Report(InstallStage.Runtime, "מוריד את סביבת ההרצה מ-Microsoft. הורדה חד-פעמית.");

            if (!await InstallRuntimeAsync(ct))
                return new InstallResult(3, "התקנת סביבת ההרצה נכשלה.");

            if (!RuntimeInstalled())
                return new InstallResult(3, "סביבת ההרצה הותקנה אך אינה מזוהה. ייתכן שנדרשת הפעלה מחדש.");

            Report(InstallStage.Runtime, "סביבת ההרצה הותקנה.");
        }

        // ---- פריסה והרצה ----

        var staging = Path.Combine(
            Path.GetTempPath(), "FilterPlus-Setup-" + Guid.NewGuid().ToString("N")[..8]);

        try
        {
            Report(InstallStage.Payload, "פורס קבצים...");

            ExtractPayload(staging);

            var script = Path.Combine(staging, "install.ps1");

            if (!File.Exists(script))
                return new InstallResult(4, "המטען פגום: install.ps1 חסר.");

            Report(InstallStage.Payload, "הקבצים נפרסו.");
            Report(InstallStage.Install, "מתקין את השירות...");

            var exit = await RunInstallScriptAsync(
                script, staging, serverUrl, PortalUrl, token, upgrade, uninstallPolicy,
                networkFloor, ct);

            if (exit != 0)
            {
                return new InstallResult(exit,
                    $"ההתקנה נכשלה (קוד {exit}). פרטים ביומן האירועים של Windows, תחת המקור FilterPlus.");
            }

            Report(InstallStage.Done, "FilterPlus הותקן.");

            return new InstallResult(0, unmanaged
                ? "המחשב נחסם."
                : "FilterPlus הותקן.");
        }
        finally
        {
            // התיקייה הזמנית מכילה תצורה עם קוד ההתקנה
            try { Directory.Delete(staging, recursive: true); }
            catch (IOException) { /* קובץ נעול. יימחק בניקוי הבא. */ }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void Report(InstallStage stage, string message, double? fraction = null)
        => _progress.Report(new InstallProgress(stage, message) { Fraction = fraction });

    // ---------------------------------------------------------------- מטען

    private static void ExtractPayload(string destination)
    {
        using var stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("payload.zip");

        if (stream is null)
        {
            throw new InvalidOperationException(
                "המתקין נבנה בלי מטען. יש להריץ את סקריפט האריזה: build/pack.ps1");
        }

        Directory.CreateDirectory(destination);

        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

        foreach (var entry in archive.Entries)
        {
            // שם ערך בארכיון עלול להכיל מעבר לתיקיית אב. ארכיון פגום
            // או זדוני היה כותב מחוץ ליעד.
            var target = Path.GetFullPath(Path.Combine(destination, entry.FullName));

            if (!target.StartsWith(destination, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"נתיב חורג בארכיון: {entry.FullName}");

            if (entry.Name.Length == 0)
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target, overwrite: true);
        }
    }

    // ---------------------------------------------------------------- הרצה

    private static async Task<int> RunInstallScriptAsync(
        string script, string payloadDir, string serverUrl, string portalUrl,
        string token, bool upgrade, string? uninstallPolicy, string? networkFloor,
        CancellationToken ct)
    {
        var info = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,

            // בלי חלון: המתקין הגרפי לא אמור להבהב מסך שחור באמצע.
            CreateNoWindow = true,

            /*
             * והפלט נשמר.
             *
             * הוא נזרק לגמרי, ולכן כשל בהתקנה החזיר "קוד 1" ותו לא.
             * הסקריפט מדפיס בדיוק היכן הוא נעצר — ומי שעמד מול מחשב
             * שנשאר בלי סוכן קיבל מספר, ואף פעם לא את הסיבה.
             *
             * זה קרה פעמיים באותו בוקר. בפעם הראשונה נדרשה שעה כדי
             * לשחזר מה קרה מיומן האירועים, ובפעם השנייה לא הייתה
             * דרך כלל.
             */
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        // ArgumentList ולא מחרוזת אחת: הבריחה נעשית על ידי המערכת,
        // ואסימון או נתיב עם רווח לא ישברו את הפקודה.
        info.ArgumentList.Add("-NoProfile");
        info.ArgumentList.Add("-NonInteractive");
        info.ArgumentList.Add("-ExecutionPolicy");
        info.ArgumentList.Add("Bypass");
        info.ArgumentList.Add("-File");
        info.ArgumentList.Add(script);
        info.ArgumentList.Add("-SourcePath");
        info.ArgumentList.Add(payloadDir);
        /*
         * שדרוג אינו מעביר כתובת שרת, ובכוונה.
         *
         * install.ps1 יודע לשמר את הכתובת הקיימת — אבל רק כשלא
         * נמסרה לו אחת. המתקין העביר אותה תמיד, גם בשדרוג, ולכן
         * השמירה ההיא לא רצה אף פעם: הסקריפט בדק
         * $PSBoundParameters.ContainsKey('ServerUrl') וקיבל true.
         *
         * נצפה בשטח. שדרוג ל-1.1.46 הסיט מחשב מ-filterplus-1-i3km
         * ל-api.filterplus.co.il בלי שאיש ביקש. שם זה היה בלתי מזיק כי
         * שתי הכתובות חיות; המנגנון עצמו הוא זה שהוציא מחשב מהישג
         * יד יום קודם, כשברירת המחדל הצביעה על שם שאינו נפתר.
         *
         * התקנה חדשה ממשיכה להעביר כתובת: שם אין מה לשמר, וברירת
         * המחדל היא בדיוק מה שצריך להיכתב.
         */
        if (!upgrade)
        {
            info.ArgumentList.Add("-ServerUrl");
            info.ArgumentList.Add(serverUrl);
        }

        info.ArgumentList.Add("-PortalUrl");
        info.ArgumentList.Add(portalUrl);
        /*
         * שלושת המצבים, וכל אחד נראה אחרת בשורת הפקודה.
         *
         * שדרוג אינו מעביר דבר: אין רישום כי המחשב כבר רשום, ואין
         * ‎-Unmanaged כי הוא מנוהל. הוא היה נופל בדיוק לענף השני
         * ומפעיל חסימה מוחלטת על מחשב תקין.
         *
         * ואסימון ריק אינו מועבר כמחרוזת ריקה אלא כדגל: בסקריפט
         * "-EnrollToken \"\"" נראה בדיוק כמו אסימון שנשכח, ושני
         * מצבים שנראים זהים הם מצב אחד שלא נבדק.
         */
        /*
         * הבחירה על אופן ההסרה, אם נעשתה.
         *
         * לא בשדרוג: שם ההגדרה כבר נקבעה בהתקנה הראשונה, והשרת
         * ממילא מתעלם מערך שמגיע אחרי שנבחר.
         */
        if (!upgrade && !string.IsNullOrWhiteSpace(uninstallPolicy))
        {
            info.ArgumentList.Add("-UninstallPolicy");
            info.ArgumentList.Add(uninstallPolicy);
        }

        /*
         * רף מדיניות הרשתות, מאותה סיבה ובאותו תנאי.
         *
         * לא בשדרוג: הרף כבר נקבע בהתקנה הראשונה, והשרת ממילא
         * מתעלם מערך שמגיע אחרי שנקבע.
         */
        if (!upgrade && !string.IsNullOrWhiteSpace(networkFloor))
        {
            info.ArgumentList.Add("-NetworkFloor");
            info.ArgumentList.Add(networkFloor);
        }

        if (upgrade)
        {
            // כלום. הרישום והחסימה שניהם לא רלוונטיים.
        }
        else if (string.IsNullOrWhiteSpace(token))
        {
            info.ArgumentList.Add("-Unmanaged");
        }
        else
        {
            info.ArgumentList.Add("-EnrollToken");
            info.ArgumentList.Add(token);
        }

        using var process = Process.Start(info)
            ?? throw new InvalidOperationException("הפעלת PowerShell נכשלה.");

        /*
         * קריאה במקביל להמתנה, ולא אחריה.
         *
         * צינור שמתמלא ואיש אינו קורא ממנו חוסם את התהליך הכותב.
         * המתנה לסיום לפני הקריאה הייתה תוקעת את ההתקנה בדיוק
         * כשהסקריפט מדפיס הרבה — כלומר כשמשהו השתבש.
         */
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);

        await process.WaitForExitAsync(ct);

        await WriteInstallLogAsync(await stdout, await stderr, process.ExitCode, ct);

        return process.ExitCode;
    }

    /// <summary>
    /// שומר את פלט ההתקנה לקובץ.
    ///
    /// תחת ProgramData ולא ליד המתקין: המתקין רץ מתיקייה זמנית
    /// שנמחקת, ומי שמנסה להבין למה ההתקנה נכשלה מחפש אחר כך.
    ///
    /// אינו זורק. כישלון ברישום אינו סיבה להפיל התקנה שהצליחה.
    /// </summary>
    private static async Task WriteInstallLogAsync(
        string stdout, string stderr, int exitCode, CancellationToken ct)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FilterPlus", "logs");

            Directory.CreateDirectory(dir);

            var path = Path.Combine(dir, $"install-{DateTime.Now:yyyyMMdd-HHmmss}.log");

            var text =
                $"FilterPlus · יומן התקנה{Environment.NewLine}" +
                $"{DateTimeOffset.Now:O}{Environment.NewLine}" +
                $"קוד יציאה: {exitCode}{Environment.NewLine}" +
                $"{new string('-', 60)}{Environment.NewLine}" +
                stdout +
                (string.IsNullOrWhiteSpace(stderr)
                    ? ""
                    : $"{Environment.NewLine}--- שגיאות ---{Environment.NewLine}{stderr}");

            await File.WriteAllTextAsync(path, text, ct);
        }
        catch (Exception)
        {
            // ראה תיאור המתודה.
        }
    }

    // ---------------------------------------------------------------- בדיקות

    /// <summary>
    /// מוריד ומתקין את סביבת ההרצה, בשקט.
    ///
    /// הכתובת היא המפנה הרשמי של מיקרוסופט לגרסה היציבה האחרונה
    /// בענף. קיבוע גרסה מדויקת היה מזדקן ומפנה בהמשך לגרסה שכבר
    /// אינה מקבלת עדכוני אבטחה.
    /// </summary>
    private async Task<bool> InstallRuntimeAsync(CancellationToken ct)
    {
        var target = Path.Combine(Path.GetTempPath(),
            $"windowsdesktop-runtime-{Guid.NewGuid().ToString("N")[..8]}.exe");

        try
        {
            using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(15) })
            using (var response = await http.GetAsync(
                RuntimeInstallerUrl, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                if (!response.IsSuccessStatusCode)
                {
                    Report(InstallStage.Runtime, $"ההורדה נכשלה: {(int)response.StatusCode}");
                    return false;
                }

                var total = response.Content.Headers.ContentLength;

                using var source = await response.Content.ReadAsStreamAsync(ct);
                using var file = File.Create(target);

                await CopyWithProgressAsync(source, file, total, ct);
            }

            Report(InstallStage.Runtime, "מתקין את סביבת ההרצה...");

            var info = new ProcessStartInfo
            {
                FileName = target,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // /quiet ללא ממשק, /norestart כדי שהמחשב לא יאותחל
            // באמצע ההתקנה שלנו ויותיר אותה חלקית
            info.ArgumentList.Add("/install");
            info.ArgumentList.Add("/quiet");
            info.ArgumentList.Add("/norestart");

            using var process = Process.Start(info);

            if (process is null) return false;

            await process.WaitForExitAsync(ct);

            // 3010 פירושו הצלחה שדורשת אתחול. סביבת ההרצה כבר שמישה,
            // ולכן ממשיכים.
            return process.ExitCode is 0 or 3010;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
        {
            Report(InstallStage.Runtime, ex.Message);
            return false;
        }
        finally
        {
            try { File.Delete(target); } catch (IOException) { }
        }
    }

    /// <summary>
    /// מעתיק ומדווח.
    ///
    /// ההורדה היא כ-60 מגה, והיא החלק הארוך בהתקנה. בלי מד התקדמות
    /// המשתמש רואה חלון תקוע ומניח שמשהו נשבר.
    /// </summary>
    private async Task CopyWithProgressAsync(
        Stream source, Stream destination, long? total, CancellationToken ct)
    {
        var buffer = new byte[81920];
        long copied = 0;
        var lastReported = -1;

        while (true)
        {
            var read = await source.ReadAsync(buffer, ct);

            if (read == 0) break;

            await destination.WriteAsync(buffer.AsMemory(0, read), ct);
            copied += read;

            if (total is not > 0) continue;

            // דיווח בכל אחוז ולא בכל מקטע: עדכון על כל 80 קילו היה
            // מציף את תור הממשק ומאט את ההורדה עצמה.
            var percent = (int)(copied * 100 / total.Value);

            if (percent == lastReported) continue;

            lastReported = percent;

            Report(InstallStage.Runtime,
                $"מוריד את סביבת ההרצה — {percent}%", percent / 100.0);
        }
    }

    /// <summary>
    /// בודק אם סביבת ההרצה קיימת, לפי תיקיות הגרסאות המשותפות.
    ///
    /// בדיקה בתיקייה ולא הרצת dotnet --list-runtimes: הפקודה תלויה
    /// ב-PATH, שעשוי להיות שונה בהקשר מורם.
    /// </summary>
    public static bool RuntimeInstalled()
    {
        foreach (var root in RuntimeRoots())
        {
            var shared = Path.Combine(root, "shared", RequiredRuntime);

            if (!Directory.Exists(shared)) continue;

            foreach (var dir in Directory.GetDirectories(shared))
            {
                var name = Path.GetFileName(dir);
                var dot = name.IndexOf('.');

                if (dot > 0
                    && int.TryParse(name[..dot], out var major)
                    && major >= RequiredMajor)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static IEnumerable<string> RuntimeRoots()
    {
        var installed = Environment.GetEnvironmentVariable("DOTNET_ROOT");

        if (!string.IsNullOrWhiteSpace(installed)) yield return installed;

        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet");
    }

    private static string? ArgValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);

        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
