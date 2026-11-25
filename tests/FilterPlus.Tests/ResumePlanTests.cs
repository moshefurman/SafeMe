using FilterPlus.Core.Updates;

namespace FilterPlus.Tests;

public sealed class ResumePlanTests
{
    /// <summary>גודל המתקין כפי שנמדד ב-1.1.26.</summary>
    private const long Installer = 64_650_547;

    [Fact]
    public void NothingOnDiskStartsOver()
    {
        var plan = ResumePlan.For(0, Installer);

        Assert.Equal(ResumeAction.StartOver, plan.Action);
        Assert.Equal(0, plan.From);
    }

    [Fact]
    public void PartialFileResumesFromWhereItStopped()
    {
        // המקרה שבשבילו כל זה נבנה: הקו נפל אחרי שליש
        var plan = ResumePlan.For(20_000_000, Installer);

        Assert.Equal(ResumeAction.Resume, plan.Action);
        Assert.Equal(20_000_000, plan.From);
    }

    [Fact]
    public void FullFileSkipsTheNetworkEntirely()
    {
        /*
         * קורה כשהניסיון הקודם הוריד הכול ונפל בדיוק לפני האימות,
         * או כשהמתקין לא הצליח לעלות. אין טעם למשוך שוב שישים מגה
         * כדי לגלות שהם כבר כאן.
         */
        var plan = ResumePlan.For(Installer, Installer);

        Assert.Equal(ResumeAction.Complete, plan.Action);
    }

    [Fact]
    public void LongerThanDeclaredStartsOver()
    {
        /*
         * לא ייתכן מהורדה תקינה. או שארית של שחרור אחר, או שמישהו
         * כתב לתיקייה הזמנית — ובשני המקרים המשך ממנו היה בונה
         * קובץ שאיננו יודעים מה הוא.
         */
        var plan = ResumePlan.For(Installer + 1, Installer);

        Assert.Equal(ResumeAction.StartOver, plan.Action);
        Assert.Equal(0, plan.From);
    }

    [Fact]
    public void OneByteShortStillResumes()
    {
        var plan = ResumePlan.For(Installer - 1, Installer);

        Assert.Equal(ResumeAction.Resume, plan.Action);
        Assert.Equal(Installer - 1, plan.From);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void UnknownExpectedSizeStartsOver(long expected)
    {
        // הצעה בלי גודל אינה ניתנת להמשך: אין מול מה למדוד
        Assert.Equal(ResumeAction.StartOver, ResumePlan.For(1_000, expected).Action);
    }

    [Fact]
    public void NegativeLengthStartsOver()
    {
        Assert.Equal(ResumeAction.StartOver, ResumePlan.For(-5, Installer).Action);
    }

    [Fact]
    public void ResumeNeverPointsPastTheEnd()
    {
        /*
         * הערך הזה נכנס ישירות לכותרת Range. נקודת המשך מעבר לסוף
         * הייתה מקבלת 416 מהשרת, ובמקרה גרוע יותר קובץ מורכב
         * שנראה תקין עד הגיבוב.
         */
        foreach (var have in new long[] { 1, 1024, Installer / 2, Installer - 1 })
        {
            var plan = ResumePlan.For(have, Installer);

            Assert.True(plan.From < Installer);
            Assert.True(plan.From > 0);
        }
    }
}
