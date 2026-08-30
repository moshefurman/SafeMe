using System.Reflection;

using SafeMe.Core.Browsing;

namespace SafeMe.Tests;

/// <summary>
/// השוואת לשוניות פתוחות מול רשימת חסימה.
///
/// זו אינה חסימה הרמטית ואסור להציג אותה ככזו: היא רואה מה נפתח
/// אחרי שנפתח, ומי שיודע מה הוא עושה יעקוף אותה. היא קיימת בשביל
/// המקרה שבו אין ספק סינון כלל — ושם היא ההבדל בין משהו לכלום.
///
/// מה שכן חייב להיות מדויק הוא ההבחנה בין מארח לכותרת, וזה מה
/// שנבדק כאן.
/// </summary>
public sealed class TabMatcherTests
{
    private static OpenTab Tab(string title, string? host = null) =>
        new() { Browser = "Chrome", Title = title, Host = host };

    // ─────────────────────────────────────────── מארח

    [Fact]
    public void MatchesTheHost()
    {
        var found = TabMatcher.Match([Tab("ChatGPT", "chatgpt.com")], ["chatgpt.com"], []);

        Assert.True(Assert.Single(found).ByHost);
    }

    /// <summary>תת-דומיין נתפס. הרשימה מדברת על האתר, לא על כתובת אחת.</summary>
    [Fact]
    public void MatchesSubdomains()
    {
        var found = TabMatcher.Match([Tab("x", "chat.openai.com")], ["openai.com"], []);

        Assert.Single(found);
    }

    [Fact]
    public void IgnoresTheWwwPrefix()
    {
        Assert.Single(TabMatcher.Match([Tab("x", "www.openai.com")], ["openai.com"], []));
    }

    /// <summary>
    /// ההשוואה על גבול נקודה, ולא הכלה במחרוזת.
    ///
    /// בלי זה, חסימת "ai.com" הייתה חוסמת גם "notai.com" — וחסימה
    /// של דומיין קצר הייתה מפילה חצי מהאינטרנט.
    /// </summary>
    [Fact]
    public void DoesNotMatchASuffixThatIsNotADomainBoundary()
    {
        Assert.Empty(TabMatcher.Match([Tab("x", "notopenai.com")], ["openai.com"], []));
    }

    // ─────────────────────────────────────────── כותרת

    [Fact]
    public void FallsBackToTheTitleWhenThereIsNoHost()
    {
        var found = TabMatcher.Match([Tab("אתר הימורים ענק")], [], ["הימורים"]);

        Assert.False(Assert.Single(found).ByHost);
    }

    /// <summary>
    /// כותרת נבדקת רק כשאין מארח.
    ///
    /// מארח ידוע שאינו ברשימה הוא תשובה, והתאמה על הכותרת אחריו
    /// הייתה מייצרת התראה על אתר שהוכח שהוא מותר — כתבה בעיתון על
    /// הימורים אינה אתר הימורים.
    /// </summary>
    [Fact]
    public void AKnownAllowedHostBeatsTheTitle()
    {
        var found = TabMatcher.Match(
            [Tab("כתבה על הימורים", "ynet.co.il")], ["chatgpt.com"], ["הימורים"]);

        Assert.Empty(found);
    }

    /// <summary>ביטוי קצר מדי נדחה. הוא היה תופס הכול.</summary>
    [Fact]
    public void ShortTermsAreRefused()
    {
        Assert.Empty(TabMatcher.Match([Tab("Mail — Israeli Chair")], [], ["ai"]));
    }

    [Fact]
    public void EveryMatchIsReturnedNotJustTheFirst()
    {
        var found = TabMatcher.Match(
            [Tab("a", "chatgpt.com"), Tab("b", "claude.ai")],
            ["chatgpt.com", "claude.ai"],
            []);

        Assert.Equal(2, found.Count);
    }

    // ─────────────────────────────────────────── מה יוצא מהמחשב

    /// <summary>
    /// הדיווח לשרת אינו יכול לשאת כתובת או כותרת.
    ///
    /// זו הבדיקה החשובה כאן, והיא על **הטיפוס** ולא על ערך. דיווח
    /// שנוסח נכון היום ייפרץ ביום שמישהו יוסיף שדה "לצורכי אבחון",
    /// והבדיקה הזו תיפול אז — בקומפילציה של הכוונה, לא אחרי שדלף.
    /// </summary>
    [Fact]
    public void TheReportHasNowhereToPutContent()
    {
        var fields = typeof(BrowsingBlockSummary)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToHashSet();

        Assert.Equal(
            new HashSet<string> { "Blocked", "ByHost", "LastAtUtc" },
            fields);
    }

    [Fact]
    public void TheSummaryCountsWithoutNaming()
    {
        var matches = TabMatcher.Match(
            [Tab("סוד גדול", "chatgpt.com"), Tab("עוד סוד")],
            ["chatgpt.com"],
            ["סוד גדול"]);

        var summary = BrowsingBlockSummary.From(matches);

        Assert.Equal(1, summary.Blocked);
        Assert.Equal(1, summary.ByHost);
    }

    [Fact]
    public void NothingBlockedMeansNoTimestamp()
    {
        Assert.Null(BrowsingBlockSummary.From([]).LastAtUtc);
    }
}
