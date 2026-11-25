using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;

namespace FilterPlus.Tests;

/// <summary>
/// הכיתוב על האייקון.
///
/// זה המקום היחיד במוצר שההורה רואה בלי לפתוח דבר, ולכן מה שנכתב
/// בו הוא החלטה ולא נוחות. השאלה שהוא שואל כשהוא מרחף מעל האייקון
/// אינה "האם מוגן" אלא "דרך מה אני יוצא, וזה מה שהגדרתי?".
/// </summary>
public sealed class TrayTooltipTests
{
    private static StatusSnapshot Snapshot(
        string? provider = "רימון", int? level = null) => new()
    {
        Status = SecurityStatus.Safe,
        ProviderDisplayName = provider,
        Headline = "החיבור מסונן",
        FilterLevel = level is null ? null : new FilterLevel { Account = level },
    };

    [Fact]
    public void ProviderComesFirst()
    {
        Assert.StartsWith("FilterPlus · רימון", TrayText.Tooltip(Snapshot()));
    }

    /// <summary>
    /// הכיתוב על האייקון אינו מפרש את רמת הסינון.
    ///
    /// היה כאן סולם שתרגם את המספר למילים, והוא הומצא: חשבון שרימון
    /// מגדירה כ"בסיסי" הוצג כ"סינון מחמיר". מספר לא מובן הוא בעיה,
    /// מילה שגויה היא נזק.
    /// </summary>
    [Fact]
    public void DoesNotInterpretTheLevel()
    {
        var text = TrayText.Tooltip(Snapshot(level: -30));

        Assert.DoesNotContain("מחמיר", text);
        Assert.DoesNotContain("-30", text);
        Assert.Contains("רימון", text);
    }

    [Fact]
    public void WithoutAProviderTheStatusLeads()
    {
        var text = TrayText.Tooltip(Snapshot(provider: null));

        Assert.StartsWith("FilterPlus · ", text);
        Assert.Contains("החיבור מסונן", text);
    }

    /// <summary>
    /// Windows חותך את הכיתוב, ולכן החיתוך נעשה כאן ובאופן צפוי.
    /// כיתוב ארוך מדי היה נחתך באמצע מילה בידי מערכת ההפעלה.
    /// </summary>
    [Fact]
    public void NeverExceedsWhatWindowsShows()
    {
        var long_ = Snapshot(provider: new string('א', 200), level: -35);

        Assert.True(TrayText.Tooltip(long_).Length <= 62);
    }

}
