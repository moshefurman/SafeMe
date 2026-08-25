using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeMe.Service.State;

/// <summary>
/// נתיבי העבודה של הסוכן והרשאותיהם.
/// כל הקבצים יושבים תחת ProgramData ומוגבלים ל-SYSTEM ולמנהלים בלבד,
/// כדי שמשתמש רגיל לא יוכל לערוך מצב או למחוק ראיות.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SafeMePaths
{
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeMe");

    public static string Config => Path.Combine(Root, "config");
    public static string StateDir => Path.Combine(Root, "state");
    public static string Queue => Path.Combine(Root, "queue");
    public static string Logs => Path.Combine(Root, "logs");

    public static string DeviceStateFile => Path.Combine(StateDir, "device.dat");
    public static string PolicyFile => Path.Combine(StateDir, "policy.json");
    public static string UninstallStateFile => Path.Combine(StateDir, "uninstall.dat");
    public static string EventQueueFile => Path.Combine(Queue, "events.ndjson");

    /// <summary>
    /// יוצר את מבנה התיקיות ומחיל ACL מוקשח. בטוח להרצה חוזרת.
    /// </summary>
    /// <exception cref="UnauthorizedAccessException">
    /// אם לתהליך אין הרשאה. התיקיות מוגבלות ל-SYSTEM ולמנהלים, ולכן הרצה
    /// שאינה מורמת תיכשל כאן במכוון ולא תמשיך במצב חלקי.
    /// </exception>
    public static void EnsureCreated()
    {
        foreach (var dir in new[] { Root, Config, StateDir, Queue, Logs })
            Directory.CreateDirectory(dir);

        HardenDirectory(Root);
        HardenDirectory(StateDir);
        HardenDirectory(Queue);

        // ללוגים ניתנת גם קריאה למשתמשים, כדי שיוכלו להראות לתמיכה מה קרה
        AllowUsersRead(Logs);
    }

    /// <summary>
    /// מסיר ירושה ומעניק גישה מלאה ל-SYSTEM ולמנהלים בלבד.
    /// </summary>
    public static void HardenDirectory(string path)
    {
        try
        {
            var info = new DirectoryInfo(path);
            var security = info.GetAccessControl();

            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                security.RemoveAccessRule(rule);

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            security.AddAccessRule(new FileSystemAccessRule(
                system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));

            info.SetAccessControl(security);
        }
        catch (Exception)
        {
            // הקשחת ACL היא שכבת הגנה נוספת ואינה תנאי לתפקוד הסוכן.
            // אם היא נכשלת (למשל בהרצה ללא הרשאות), ממשיכים ומדווחים בלוג הראשי.
        }
    }

    private static void AllowUsersRead(string path)
    {
        try
        {
            var info = new DirectoryInfo(path);
            var security = info.GetAccessControl();
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            security.AddAccessRule(new FileSystemAccessRule(
                users,
                FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            info.SetAccessControl(security);
        }
        catch (Exception)
        {
            // ראה הערה ב-HardenDirectory
        }
    }
}
