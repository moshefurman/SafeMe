using SafeMe.Core.Policy;
using SafeMe.Core.Security;

namespace SafeMe.Core.Models;

public sealed class EnrollRequest
{
    public required string Hwid { get; set; }
    public string MachineName { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string AgentVersion { get; set; } = "";

    /// <summary>
    /// אסימון רישום שמונפק מהפורטל. מקודד את הדייר ואת פרופיל ההתקנה,
    /// חד-פעמי או מוגבל-שימושים, ופג תוקף. מחליף את מפתח הרישיון הישן,
    /// שהיה קבוע ולכן ניתן לשכפול בין מכשירים.
    /// </summary>
    public string? EnrollToken { get; set; }

    public Guid InstallId { get; set; }
}

public sealed class EnrollResponse
{
    public Guid DeviceId { get; set; }
    public string DeviceToken { get; set; } = "";
    public string? PolicyEtag { get; set; }
    public UninstallKeyMode UninstallKeyMode { get; set; } = UninstallKeyMode.Rsa;

    /// <summary>מפתח ציבורי של השרת (PEM) לאימות קודי הסרה ולאימות חתימת מדיניות.</summary>
    public string? ServerPublicKeyPem { get; set; }

    /// <summary>
    /// מפתח ציבורי נפרד לאימות קודי הסרה בלבד.
    ///
    /// ההסרה חייבת לעבור דרך החברה. כל עוד הקוד מאומת במפתח
    /// המדיניות, מי שמשיג את היכולת לחתום מדיניות מקבל גם את
    /// היכולת להסיר כל מכשיר — ושתי הסמכויות האלה לא אמורות
    /// לנסוע יחד.
    /// </summary>
    public string? UninstallPublicKeyPem { get; set; }

    /// <summary>
    /// מפתח ציבורי נפרד לאימות היתרי הקלה בלבד.
    ///
    /// ההפרדה היא כל ההגנה מאחורי "להחמיר כן, להסיר לא": שרת שנפרץ
    /// ומסוגל לחתום מדיניות אינו מסוגל בכך גם להקל אותה מתחת לרצפה.
    /// אם הוא זהה למפתח המדיניות, ההיתר נדחה.
    /// </summary>
    public string? LooseningPublicKeyPem { get; set; }

    /// <summary>סוד מכשיר, מאוכלס רק כאשר UninstallKeyMode הוא Hmac.</summary>
    public string? DeviceSecret { get; set; }

    /// <summary>family_child, individual או organization.</summary>
    public string? InstallProfile { get; set; }

    /// <summary>
    /// מצב האכיפה ההתחלתי, נקבע בהתקנה. העלאתו מרחוק מותרת,
    /// הורדתו דורשת היתר הקלה חתום. ראה 3.2 באפיון.
    /// </summary>
    public EnforcementMode EnforcementMode { get; set; } = EnforcementMode.Enforce;

    /// <summary>רצפת המדיניות, חתומה. המכשיר מאמת ושומר אותה מוגנת.</summary>
    public SignedEnvelope? PolicyFloor { get; set; }

    public string? SigningKid { get; set; }

    public DateTimeOffset? LicenseExpiresUtc { get; set; }
}

public sealed class NetworkAdapterInfo
{
    public string Name { get; set; } = "";
    public string? Ssid { get; set; }
    public string? Gateway { get; set; }
    public string? LocalIp { get; set; }
    public string? Description { get; set; }

    /// <summary>true אם המתאם נראה כמתאם VPN וירטואלי (TAP, WinTun, WireGuard).</summary>
    public bool IsVirtualVpn { get; set; }
}

public sealed class HeartbeatRequest
{
    public required string Hwid { get; set; }
    public string AgentVersion { get; set; } = "";
    public int PolicyVersion { get; set; }
    public DateTimeOffset SentUtc { get; set; } = DateTimeOffset.UtcNow;
    public long Sequence { get; set; }
    public SecurityStatus Status { get; set; }
    public int Score { get; set; }
    public EnforcementMode Enforcement { get; set; }
    public List<NetworkAdapterInfo> ActiveAdapters { get; set; } = new();
    public string? PublicIp { get; set; }
    public string? DetectedProvider { get; set; }
    public List<string> FailedProbes { get; set; } = new();
    public List<TamperEvent> TamperEvents { get; set; } = new();
    public int WfpFilterCount { get; set; }
    public long UptimeSec { get; set; }
    public bool LockoutActive { get; set; }
}

public sealed class HeartbeatResponse
{
    public bool Ok { get; set; }
    public DateTimeOffset ServerUtc { get; set; }
    public string? PolicyEtag { get; set; }
    public DateTimeOffset? LicenseExpiresUtc { get; set; }
    public bool LicenseValid { get; set; } = true;
    public List<RemoteCommand> Commands { get; set; } = new();
}

public sealed class RemoteCommand
{
    public Guid Id { get; set; }

    /// <summary>RefreshPolicy, Lockout, ReleaseLockout, RunAudit, Uninstall</summary>
    public string Type { get; set; } = "";

    public Dictionary<string, string> Args { get; set; } = new();
}

public sealed class UninstallChallengeRequest
{
    public required string Challenge { get; set; }
    public string? OperatorId { get; set; }
    public string? Reason { get; set; }
}

public sealed class UninstallChallengeResponse
{
    public string Response { get; set; } = "";
    public DateTimeOffset ExpiresUtc { get; set; }
}

/// <summary>
/// תשובת מדיניות. מכילה מעטפה חתומה ולא JSON גולמי, כדי שהסוכן יאמת
/// חתימה על הבתים שהגיעו ולא על ייצוג שהוא בנה מחדש. ראה 5.2 באפיון.
/// </summary>
public sealed class PolicyResponse
{
    public SignedEnvelope? Envelope { get; set; }
    public string? Etag { get; set; }
    public bool NotModified { get; set; }
}
