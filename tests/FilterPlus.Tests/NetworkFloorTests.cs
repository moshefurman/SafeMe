namespace FilterPlus.Tests;

/// <summary>
/// סדר החומרה של מדיניות הרשתות.
///
/// הרף שנקבע בהתקנה מגביל את מה שאפשר לבחור אחר כך: להחמיר תמיד
/// מותר, ולהקל מעבר לרף — לא. הסדר הזה מוגדר בשלושה מקומות —
/// אילוץ במסד, שאילתת העדכון, והמסך — ואם אחד מהם יתהפך, ההגבלה
/// תיאכף הפוך: היא תחסום החמרה ותתיר הקלה.
///
/// זו טעות שקטה במיוחד, כי המסך ימשיך להיראות תקין.
/// </summary>
public class NetworkFloorTests
{
    /// <summary>אותו דירוג בדיוק שבשאילתות: קטן יותר = מחמיר יותר.</summary>
    private static int Rank(string policy) => policy switch
    {
        "strict" => 1,
        "balanced" => 2,
        _ => 3,
    };

    private static bool Allowed(string wanted, string floor) => Rank(wanted) <= Rank(floor);

    [Theory]
    // רף מקל — הכול מותר
    [InlineData("strict", "lenient", true)]
    [InlineData("balanced", "lenient", true)]
    [InlineData("lenient", "lenient", true)]
    // רף אמצעי — אפשר להחמיר, אי אפשר להקל
    [InlineData("strict", "balanced", true)]
    [InlineData("balanced", "balanced", true)]
    [InlineData("lenient", "balanced", false)]
    // רף מחמיר — רק הוא עצמו
    [InlineData("strict", "strict", true)]
    [InlineData("balanced", "strict", false)]
    [InlineData("lenient", "strict", false)]
    public void Only_tightening_is_allowed(string wanted, string floor, bool allowed)
    {
        Assert.Equal(allowed, Allowed(wanted, floor));
    }

    [Fact]
    public void Tightening_is_never_blocked()
    {
        /*
         * הכיוון שאסור להישבר.
         *
         * הורה שמבקש להדק עושה בדיוק את מה שהמוצר קיים בשבילו,
         * וחסימה שלו הופכת את ההגנה למכשול. אם הדירוג יתהפך אי
         * פעם, זו הבדיקה שתיפול ראשונה.
         */
        foreach (var floor in new[] { "strict", "balanced", "lenient" })
            Assert.True(Allowed("strict", floor));
    }
}
