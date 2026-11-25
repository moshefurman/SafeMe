using FilterPlus.Core.Updates;

namespace FilterPlus.Tests;

public sealed class UpdateMarkerTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 31, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void FreshMarkerSilencesTheWatchdogs()
    {
        Assert.True(UpdateMarker.IsActive(UpdateMarker.Stamp(Now), Now));
    }

    [Fact]
    public void MarkerStaysValidForTheWholeInstall()
    {
        // ההתקנה נמדדה בעשרות שניות. ארבע דקות הן עדיין בתוך החלון.
        var written = UpdateMarker.Stamp(Now);

        Assert.True(UpdateMarker.IsActive(written, Now.AddMinutes(4)));
    }

    [Fact]
    public void ExpiredMarkerStopsSilencingThem()
    {
        /*
         * מתקין שקרס בלי לנקות היה משתיק את השומרים לנצח — כלומר
         * מחשב בלי שמירה, בדיוק אחרי ניסיון עדכון שנפל.
         */
        var written = UpdateMarker.Stamp(Now);

        Assert.False(UpdateMarker.IsActive(written, Now.AddMinutes(6)));
    }

    [Fact]
    public void FutureStampIsNotHonoured()
    {
        /*
         * זו הדרך הזולה לנטרל את השומרים: לכתוב תאריך רחוק ולהשאיר
         * אותם ישנים. שעון שקפץ קדימה מייצר את אותו מצב בטעות.
         */
        var future = UpdateMarker.Stamp(Now.AddHours(2));

        Assert.False(UpdateMarker.IsActive(future, Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a date")]
    [InlineData("0")]
    public void UnreadableMarkerKeepsTheWatchdogsAwake(string? content)
    {
        // הכיוון הבטוח: קובץ פגום אינו סיבה להשבית הגנה.
        Assert.False(UpdateMarker.IsActive(content, Now));
    }

    [Fact]
    public void MarkerLivesWhereBothServicesCanReachIt()
    {
        /*
         * שירות השומר הוא פרויקט נפרד שאינו מכיר את נתיבי הסוכן,
         * ולכן ההסכמה על המקום חייבת לשבת ב-Core. הנתיב נבדק כאן
         * כדי ששינוי בו לא יעבור בשקט ויפרק את ההסכם.
         */
        Assert.EndsWith(Path.Combine("FilterPlus", "state", "update.lock"), UpdateMarker.Path);
    }
}
