using SafeMe.Core.Policy;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// קריאת רמת הסינון מדף החסימה.
///
/// המחרוזת נמדדה על מכונה מסוננת אמיתית ולא נבנתה לצורך הבדיקה:
/// רימון החזירה אותה בגוף התשובה כשחסמה יעד.
/// </summary>
public class FilterLevelTests
{
    private const string Measured =
        "level=-30&url=http%3A%2F%2Fwww.bet365.com%2F&cause=url_level"
        + "&urllevel=-35&user_id=474870&sigid=1f06c9ddf439153&category=41";

    [Fact]
    public void The_measured_body_is_read_correctly()
    {
        var level = FilterLevelReader.Read(Measured);

        Assert.Equal(-30, level.Account);
        Assert.Equal(-35, level.Required);
        Assert.Equal(41, level.Category);
        Assert.Equal("url_level", level.Cause);
    }

    /// <summary>
    /// "urllevel" מכיל בתוכו "level".
    ///
    /// בלי גבול שמונע אות לפני, הרמה של החשבון הייתה נקראת מתוך
    /// urllevel — ושני המספרים היו יוצאים זהים. השגיאה הזו אינה
    /// נראית: היא מחזירה מספר סביר, פשוט לא הנכון.
    /// </summary>
    [Fact]
    public void Account_level_is_not_read_out_of_urllevel()
    {
        var level = FilterLevelReader.Read("urllevel=-35&level=-30");

        Assert.Equal(-30, level.Account);
        Assert.Equal(-35, level.Required);
        Assert.NotEqual(level.Account, level.Required);
    }

    [Fact]
    public void The_order_in_the_body_does_not_matter()
    {
        var a = FilterLevelReader.Read("level=-30&urllevel=-35");
        var b = FilterLevelReader.Read("urllevel=-35&level=-30");

        Assert.Equal(a.Account, b.Account);
        Assert.Equal(a.Required, b.Required);
    }

    /// <summary>
    /// מזהי החשבון אינם נקראים, ובמכוון.
    ///
    /// אין בהם צורך לתפקוד המוצר, ואיסוף מידע שאין בו צורך הוא
    /// מה שהופך כלי הגנה לכלי מעקב.
    /// </summary>
    [Fact]
    public void Account_identifiers_are_not_extracted()
    {
        var level = FilterLevelReader.Read(Measured);
        var text = FilterLevelReader.Describe(level);

        Assert.DoesNotContain("474870", text);
        Assert.DoesNotContain("1f06c9dd", text);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("<html>דף רגיל בלי שום רמה</html>")]
    public void Nothing_to_read_yields_an_empty_result(string? body)
    {
        var level = FilterLevelReader.Read(body);

        Assert.False(level.HasAny);
        Assert.Equal("רמת הסינון אינה ידועה.", FilterLevelReader.Describe(level));
    }

    [Theory]
    [InlineData(-45, "מחמירה מאוד")]
    [InlineData(-30, "מחמירה")]
    [InlineData(-15, "בינונית")]
    [InlineData(-5, "מקלה")]
    [InlineData(0, "מקלה מאוד")]
    public void The_level_is_explained_not_just_shown(int account, string expected)
    {
        var text = FilterLevelReader.Describe(new FilterLevel { Account = account });

        Assert.Contains(expected, text);
        Assert.Contains(account.ToString(), text);
    }
}
