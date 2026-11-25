using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace FilterPlus.Service.Net;

/// <summary>
/// מאתר את כלי המנהור המותקנים על המחשב.
///
/// WFP מזהה יישום לפי הנתיב שלו, לא לפי שמו. המדיניות מגיעה מהשרת
/// עם שמות קבצים — "wireguard.exe" — ומישהו צריך לתרגם אותם לנתיבים
/// שאפשר לחסום. זה מה שהמחלקה הזו עושה.
///
/// שני מקורות, ובסדר הזה:
///
/// תהליכים שרצים כרגע הם המקור המדויק. כשתוכנה רצה, הנתיב שלה ידוע
/// בוודאות — גם אם הותקנה לתיקייה שאיש לא היה מנחש. זה תופס גם קובץ
/// שהורד לתיקיית ההורדות והורץ משם.
///
/// סריקת תיקיות ההתקנה תופסת את מה שמותקן אך אינו רץ, כדי שהחסימה
/// תהיה במקום עוד לפני ההפעלה הראשונה.
///
/// מה שהמחלקה הזו **אינה** תופסת: קובץ ששונה שמו. זו הסיבה שחסימת
/// היישומים היא שכבה משלימה בלבד. מה שמחזיק הוא חסימת הפורטים, שאינה
/// יודעת ולא אכפת לה איך התוכנה נקראת.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TunnelLocator
{
    /// <summary>עומק הסריקה בתיקיות ההתקנה. מספיק לתבנית יצרן\\מוצר\\bin.</summary>
    private const int MaxDepth = 4;

    /// <summary>תקרה לכמות הקבצים שנבדקים, כדי שסריקה לא תיהפך לעומס.</summary>
    private const int MaxExamined = 40_000;

    private readonly ILogger<TunnelLocator> _log;

    public TunnelLocator(ILogger<TunnelLocator> log) => _log = log;

    /// <summary>
    /// מחזיר נתיבים מלאים לכל קובץ הרצה ששמו ברשימה.
    /// </summary>
    public IReadOnlyList<string> Locate(IEnumerable<string> processNames)
    {
        var wanted = new HashSet<string>(
            processNames.Select(n => n.Trim()).Where(n => n.Length > 0),
            StringComparer.OrdinalIgnoreCase);

        if (wanted.Count == 0) return [];

        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        FromRunningProcesses(wanted, found);
        FromInstallDirectories(wanted, found);

        if (found.Count > 0)
            _log.LogInformation("אותרו {Count} כלי מנהור לחסימה.", found.Count);

        return [.. found.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// תהליכים שרצים כרגע.
    ///
    /// שליפת הנתיב של תהליך זר עלולה להיכשל — הרשאות, תהליך מערכת,
    /// או תהליך שנסגר בין השורות. כל כשל נבלע בשקט: הוא לגמרי צפוי,
    /// ורישום שלו היה מציף את היומן בכל סריקה.
    /// </summary>
    private void FromRunningProcesses(HashSet<string> wanted, HashSet<string> found)
    {
        Process[] processes;

        try
        {
            processes = Process.GetProcesses();
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "מניית התהליכים נכשלה.");
            return;
        }

        foreach (var process in processes)
        {
            try
            {
                if (!wanted.Contains(process.ProcessName + ".exe")) continue;

                var path = process.MainModule?.FileName;

                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                {
                    found.Add(path);
                    _log.LogWarning("כלי מנהור פעיל: {Path}", path);
                }
            }
            catch
            {
                // צפוי לחלוטין. ראה הערת התיעוד.
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    /// <summary>סריקת תיקיות ההתקנה המקובלות.</summary>
    private void FromInstallDirectories(HashSet<string> wanted, HashSet<string> found)
    {
        var examined = 0;

        foreach (var root in InstallRoots())
        {
            if (examined >= MaxExamined) break;
            if (!Directory.Exists(root)) continue;

            Scan(root, wanted, found, 0, ref examined);
        }
    }

    private void Scan(
        string directory, HashSet<string> wanted, HashSet<string> found,
        int depth, ref int examined)
    {
        if (depth > MaxDepth || examined >= MaxExamined) return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*.exe"))
            {
                if (++examined >= MaxExamined) return;

                if (wanted.Contains(Path.GetFileName(file)))
                    found.Add(file);
            }

            foreach (var sub in Directory.EnumerateDirectories(directory))
            {
                if (examined >= MaxExamined) return;

                Scan(sub, wanted, found, depth + 1, ref examined);
            }
        }
        catch (UnauthorizedAccessException)
        {
            // תיקייה שאין אליה גישה. אין מה לדווח.
        }
        catch (DirectoryNotFoundException)
        {
            // נמחקה בזמן הסריקה.
        }
        catch (IOException)
        {
            // כונן רשת שנותק, נקודת עגינה שבורה.
        }
    }

    /// <summary>
    /// היכן מחפשים.
    ///
    /// כולל את תיקיות המשתמש ואת ההורדות, ולא רק את Program Files:
    /// חלק גדול מכלי המנהור מותקנים בלי הרשאות מנהל בדיוק כדי שלא
    /// יידרש אישור, ורבים פשוט מורצים מהמקום שאליו הורדו.
    /// </summary>
    private static IEnumerable<string> InstallRoots()
    {
        var roots = new List<string>();

        void Add(Environment.SpecialFolder folder)
        {
            var path = Environment.GetFolderPath(folder);

            if (!string.IsNullOrWhiteSpace(path)) roots.Add(path);
        }

        Add(Environment.SpecialFolder.ProgramFiles);
        Add(Environment.SpecialFolder.ProgramFilesX86);
        Add(Environment.SpecialFolder.LocalApplicationData);
        Add(Environment.SpecialFolder.ApplicationData);

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (!string.IsNullOrWhiteSpace(profile))
        {
            roots.Add(Path.Combine(profile, "Downloads"));
            roots.Add(Path.Combine(profile, "Desktop"));
        }

        return roots.Distinct(StringComparer.OrdinalIgnoreCase);
    }
}
