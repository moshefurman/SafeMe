using System.Text.Json.Serialization;

namespace SafeMe.Core.Models;

/// <summary>תמונת מצב שמוצגת ב-TrayApp. מוחזרת דרך IPC בפעולת GET_STATUS.</summary>
public sealed class StatusSnapshot
{
    public SecurityStatus Status { get; set; } = SecurityStatus.Unknown;

    /// <summary>ציון ביקורת 0-100.</summary>
    public int Score { get; set; }

    /// <summary>מזהה הספק שזוהה (netfree/etrog/rimon/...), או null.</summary>
    public string? ProviderId { get; set; }

    /// <summary>שם התצוגה בעברית של הספק.</summary>
    public string? ProviderDisplayName { get; set; }

    public TrustLevel ProviderTrust { get; set; } = TrustLevel.None;

    /// <summary>רמת הסינון כפי שהספק מדווח. null כשלא נקראה.</summary>
    public SafeMe.Core.Policy.FilterLevel? FilterLevel { get; set; }

    public EnforcementMode Enforcement { get; set; } = EnforcementMode.Monitor;

    /// <summary>
    /// עמדת היציאה הנוכחית: Off, Filtered, ProviderOnly, LockedDown.
    ///
    /// נשמרת כמחרוזת ולא כ-enum כי היא נוסעת לשרת ולמגש, ותוספת
    /// ערך בעתיד לא צריכה לשבור סוכן ישן שקורא אותה.
    /// </summary>
    public string? EgressPosture { get; set; }

    public bool LockoutActive { get; set; }
    public DateTimeOffset? LockoutUntil { get; set; }
    public string? LockoutReason { get; set; }

    public string? PublicIp { get; set; }
    public string? ReverseDns { get; set; }
    public string? ActiveAdapter { get; set; }
    public string? WifiSsid { get; set; }

    public int PolicyVersion { get; set; }
    public DateTimeOffset? LastAuditUtc { get; set; }
    public DateTimeOffset? LastHeartbeatUtc { get; set; }
    public DateTimeOffset? LastServerContactUtc { get; set; }

    public bool LicenseValid { get; set; }
    public DateTimeOffset? LicenseExpiresUtc { get; set; }

    public int WfpFilterCount { get; set; }
    /// <summary>
    /// הגרסה שרצה בפועל.
    ///
    /// הייתה כאן ברירת מחדל "1.0.0", ואיש לא הציב ערך במקומה — ולכן
    /// המסך הראה 1.0.0 בכל גרסה שהיא. ברירת מחדל שנראית כמו נתון
    /// אמיתי גרועה מריק: היא אינה נראית שגויה, ולכן איש אינו בודק.
    /// </summary>
    public string AgentVersion { get; set; } = "";
    public long UptimeSeconds { get; set; }

    /// <summary>הודעה קצרה בעברית לתצוגה מיידית למשתמש.</summary>
    public string Headline { get; set; } = "";

    /// <summary>פירוט הגששים שנכשלו, לתצוגה בחלון הסטטוס.</summary>
    public List<ProbeSummary> FailedProbes { get; set; } = new();

    [JsonIgnore]
    public bool IsStale => LastAuditUtc is null ||
        DateTimeOffset.UtcNow - LastAuditUtc.Value > TimeSpan.FromMinutes(30);
}

public sealed class ProbeSummary
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public ProbeSeverity Severity { get; set; }
    public string? Detail { get; set; }
}
