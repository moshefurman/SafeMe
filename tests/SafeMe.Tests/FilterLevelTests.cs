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

    /// <summary>
    /// השם מגיע מהדף, ולא מפרשנות של המספר.
    ///
    /// כאן היה סולם שתרגם טווחים לתיאורים — "מחמירה", "בינונית",
    /// "מקלה" — והוא הומצא. מדידה מול חשבון אמיתי הראתה שרימון
    /// מגדירה level=-30 כ"בסיסית", בעוד הסולם קרא לו "מחמירה":
    /// ההפך המדויק, על הדבר היחיד שההורה בא לוודא.
    ///
    /// הספק כותב את השם בדף בעצמו, ולכן אין מה לנחש.
    /// </summary>
    [Fact]
    public void The_name_comes_from_the_page()
    {
        const string body = "<span>בסיסית</span>&nbsp;בה לא ניתן לצפות בדף זה"
            + "?level=-30&urllevel=-40&category=56";

        var level = FilterLevelReader.Read(body, ["בסיסית", "בינונית", "גבוהה", "הרמטית"]);

        Assert.Equal("בסיסית", level.Name);
        Assert.Equal(-30, level.Account);
        Assert.Contains("בסיסית", FilterLevelReader.Describe(level));
    }

    /// <summary>
    /// רשימה סגורה יכולה רק לא למצוא.
    ///
    /// חילוץ בתבנית היה תופס כל מילה שיושבת במקום הנכון בדף, וכל
    /// שינוי עיצוב היה מייצר "דרגה" שאינה קיימת.
    /// </summary>
    [Fact]
    public void An_unknown_name_is_not_invented()
    {
        var level = FilterLevelReader.Read("<span>משהו אחר</span>?level=-30", ["בסיסית"]);

        Assert.Null(level.Name);
        Assert.Equal(-30, level.Account);
    }

    /// <summary>בלי שם מוצג המספר, ובלי פרשנות שלו.</summary>
    [Fact]
    public void Without_a_name_only_the_number_is_shown()
    {
        var text = FilterLevelReader.Describe(FilterLevelReader.Read("?level=-30", []));

        Assert.Contains("-30", text);
        Assert.DoesNotContain("מחמיר", text);
    }
}
