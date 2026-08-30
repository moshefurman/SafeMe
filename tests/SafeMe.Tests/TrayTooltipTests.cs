using SafeMe.Core.Models;
using SafeMe.Core.Policy;

namespace SafeMe.Tests;

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
        Assert.StartsWith("SafeMe · רימון", TrayText.Tooltip(Snapshot()));
    }

    [Fact]
    public void LevelIsShownWhenKnown()
    {
        var text = TrayText.Tooltip(Snapshot(level: -30));

        // המספר אינו מופיע כאן. הוא שייך למסך הפירוט בלבד.
        Assert.Contains("סינון מחמיר", text);
        Assert.DoesNotContain("-30", text);
    }

    /// <summary>
    /// רמה שלא נקראה אינה מומצאת. היעדר ידיעה מוצג כהיעדר שורה,
    /// ולא כמספר שנראה כאילו נמדד.
    /// </summary>
    [Fact]
    public void UnknownLevelIsSimplyAbsent()
    {
        Assert.DoesNotContain("סינון", TrayText.Tooltip(Snapshot()));
    }

    [Fact]
    public void WithoutAProviderTheStatusLeads()
    {
        var text = TrayText.Tooltip(Snapshot(provider: null));

        Assert.StartsWith("SafeMe · ", text);
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

    [Theory]
    [InlineData(-45, "סינון מחמיר מאוד")]
    [InlineData(-30, "סינון מחמיר")]
    [InlineData(-15, "סינון בינוני")]
    [InlineData(-5, "סינון מקל")]
    [InlineData(10, "סינון מקל מאוד")]
    public void StrictnessIsNamedNotJustNumbered(int account, string expected)
    {
        Assert.Contains(expected, TrayText.Tooltip(Snapshot(level: account)));
    }
}
