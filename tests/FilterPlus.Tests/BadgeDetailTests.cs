using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;

namespace FilterPlus.Tests;

/// <summary>
/// השורה התחתונה בתג הצף.
///
/// זהו הטקסט היחיד שנמצא על המסך כל הזמן, בלי ריחוף ובלי לחיצה,
/// ולכן מה שנכתב בו הוא ההודעה שהמוצר מוסר לאורך היום. הוא הראה
/// את הציון — המספר הפחות מעניין מבין השלושה, כי הוא אומר כמה
/// מהבדיקות שלנו עברו ולא כמה הספק מחמיר.
/// </summary>
public sealed class BadgeDetailTests
{
    private static StatusSnapshot Snapshot(
        SecurityStatus status = SecurityStatus.Safe,
        string? provider = "רימון",
        int? level = null,
        int score = 100) => new()
    {
        Status = status,
        ProviderDisplayName = provider,
        Score = score,
        FilterLevel = level is null ? null : new FilterLevel { Account = level },
    };

    private static string Detail(StatusSnapshot snapshot) =>
        TrayText.BadgeDetail(snapshot);

    [Fact]
    public void ShowsProviderAndLevelTogether()
    {
        /*
         * מילה, לא מספר.
         *
         * "רמה -30" אינו אומר דבר לאיש: הוא שלילי, והוא הפוך
         * לאינטואיציה — נמוך יותר מחמיר יותר. הורה שרואה אותו אינו
         * יודע אם זה טוב או רע, ובוודאי לא אם זה מה שהוא ביקש.
         */
        Assert.Equal("רימון", Detail(Snapshot(level: -30)));
    }

    /// <summary>
    /// דרגה שלא נקראה אינה מומצאת, והשם נשאר. זה המצב הרגיל
    /// בדקות הראשונות אחרי התקנה.
    /// </summary>
    [Fact]
    public void FallsBackToTheNameAlone()
    {
        Assert.Equal("רימון", Detail(Snapshot()));
    }

    /// <summary>
    /// "רמה -30" לבדה אינה אומרת דבר בלי לדעת של מי, ולכן בלי ספק
    /// מזוהה אין מה לצרף.
    /// </summary>
    [Fact]
    public void WithoutAProviderThereIsNothingToJoin()
    {
        Assert.Equal("ציון 100", Detail(Snapshot(provider: null)));
    }

    [Fact]
    public void PartialFilteringAlsoShowsTheLevel()
    {
        Assert.Equal("רימון", Detail(Snapshot(SecurityStatus.LowFilter, level: -12)));
    }

    [Theory]
    [InlineData(SecurityStatus.Unfiltered, "החיבור אינו מוגן")]
    [InlineData(SecurityStatus.Blocked, "נעילה פעילה")]
    [InlineData(SecurityStatus.Unknown, "אין קשר לשירות")]
    public void OtherStatesSayWhatTheyAre(SecurityStatus status, string expected)
    {
        Assert.Equal(expected, Detail(Snapshot(status)));
    }
}
