using System.Text.Json;

namespace FilterPlus.Core.Ipc;

/// <summary>שמות הפעולות הנתמכות בערוץ ה-IPC.</summary>
public static class IpcOps
{
    public const string Ping = "PING";
    public const string GetStatus = "GET_STATUS";
    public const string RunAuditNow = "RUN_AUDIT_NOW";

    /// <summary>
    /// מבקש פעימה מיידית מול השרת, בלי להמתין למחזור הבא.
    ///
    /// אישור רשת או שינוי מדיניות יושבים על השרת, והסוכן קולט אותם
    /// רק בפעימה. בלי זה הורה שאישר רשת המתין עד שלוש דקות, או
    /// הפעיל מחדש את המחשב כדי "לזרז". הפעולה הזו היא אותו זירוז,
    /// בלחיצה: היא מעירה את לולאת הפעימה, וזו מושכת מדיניות ואת
    /// פסק הרשת ומחילה אותם מיד.
    /// </summary>
    public const string RefreshNow = "REFRESH_NOW";

    public const string GetPolicy = "GET_POLICY";
    public const string UninstallChallenge = "UNINSTALL_CHALLENGE";
    public const string UninstallVerify = "UNINSTALL_VERIFY";
    public const string LockoutState = "LOCKOUT_STATE";


    /// <summary>פעולות שדורשות לקוח מורם (Elevated).</summary>
    public static readonly HashSet<string> RequiresElevation = new(StringComparer.OrdinalIgnoreCase)
    {
        UninstallChallenge, UninstallVerify, LockoutState
    };
}

public static class IpcConstants
{
    public const string PipeName = "FilterPlus.Agent.v1";
    public const int MaxMessageBytes = 512 * 1024;
    public const int ConnectTimeoutMs = 4000;
}

public sealed class IpcRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Op { get; set; } = "";

    /// <summary>גוף הבקשה כ-JSON גולמי, מפוענח לפי סוג הפעולה.</summary>
    public JsonElement? Payload { get; set; }
}

public sealed class IpcResponse
{
    public Guid Id { get; set; }
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public object? Payload { get; set; }

    public static IpcResponse Success(Guid id, object? payload = null) =>
        new() { Id = id, Ok = true, Payload = payload };

    public static IpcResponse Failure(Guid id, string error) =>
        new() { Id = id, Ok = false, Error = error };
}

public sealed class PingPayload
{
    public string Version { get; set; } = "";
    public long UptimeSec { get; set; }
}

public sealed class UninstallChallengePayload
{
    public string? Reason { get; set; }
}

public sealed class UninstallChallengeResult
{
    public string Challenge { get; set; } = "";
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>Rsa או Hmac. קובע אם המסך מציג שדה קצר או שדה הדבקה ארוך.</summary>
    public string Mode { get; set; } = "Rsa";
}

public sealed class UninstallVerifyPayload
{
    public string Challenge { get; set; } = "";
    public string Response { get; set; } = "";
}

public sealed class UninstallVerifyResult
{
    public bool Granted { get; set; }

    /// <summary>אסימון חד-פעמי שמוצג ל-msiexec כהוכחה שההסרה אושרה.</summary>
    public string? Token { get; set; }

    public int AttemptsLeft { get; set; }
    public DateTimeOffset? LockoutUntil { get; set; }

    /// <summary>הודעה בעברית להצגה למשתמש.</summary>
    public string Message { get; set; } = "";
}

public sealed class LockoutStateResult
{
    public bool Active { get; set; }
    public DateTimeOffset? Until { get; set; }
    public string? Reason { get; set; }
}
