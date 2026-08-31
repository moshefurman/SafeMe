using SafeMe.Core.Policy;

namespace SafeMe.Tests;

public sealed class OfflineExpiryTests
{
    private static readonly DateTimeOffset Installed = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const int Window = 60;

    [Fact]
    public void FreshContactKeepsEnforcing()
    {
        var now = Installed.AddDays(100);

        Assert.Equal(
            OfflineState.Live,
            OfflineExpiry.Evaluate(now.AddHours(-1), Installed, now, Window));
    }

    [Fact]
    public void SilenceEventuallyReleases()
    {
        var last = Installed.AddDays(10);

        Assert.Equal(
            OfflineState.Expired,
            OfflineExpiry.Evaluate(last, Installed, last.AddDays(Window), Window));
    }

    [Fact]
    public void WarningComesBeforeExpiry()
    {
        var last = Installed.AddDays(10);

        // שלושת רבעי הדרך. מוקדם מדי הופך את האזהרה לרעש.
        Assert.Equal(
            OfflineState.Live,
            OfflineExpiry.Evaluate(last, Installed, last.AddDays(44), Window));

        Assert.Equal(
            OfflineState.Warning,
            OfflineExpiry.Evaluate(last, Installed, last.AddDays(46), Window));
    }

    [Fact]
    public void FreshInstallIsNotBornExpired()
    {
        /*
         * המקרה שהיה שובר הכול: מחשב שהותקן ועוד לא הספיק לדבר עם
         * השרת. בלי נקודת ייחוס, היעדר מגע נראה כמו ניתוק אינסופי
         * וכל התקנה הייתה משוחררת מאכיפה לפני הפעימה הראשונה.
         */
        Assert.Equal(
            OfflineState.Live,
            OfflineExpiry.Evaluate(null, Installed, Installed.AddMinutes(5), Window));
    }

    [Fact]
    public void NeverContactedStillExpiresEventually()
    {
        // אבל מחשב שהותקן ומעולם לא דיבר גם הוא משתחרר בסוף.
        Assert.Equal(
            OfflineState.Expired,
            OfflineExpiry.Evaluate(null, Installed, Installed.AddDays(Window), Window));
    }

    [Fact]
    public void ClockJumpBackwardsDoesNotDisableExpiry()
    {
        /*
         * מגע "עתידי" מייצר משך שלילי, וכל השוואה תמימה הייתה
         * מחזירה Live לנצח — כלומר הזזת שעון הייתה מבטלת את
         * המנגנון. זו הדרך הזולה ביותר לנטרל אותו.
         */
        var now = Installed.AddDays(30);

        Assert.Equal(
            OfflineState.Live,
            OfflineExpiry.Evaluate(now.AddDays(500), Installed, now, Window));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ZeroWindowMeansNoExpiryAtAll(int window)
    {
        // ארגון שמפעיל שרת משלו רשאי לכבות. זו אינה ברירת המחדל.
        Assert.Equal(
            OfflineState.Live,
            OfflineExpiry.Evaluate(Installed, Installed, Installed.AddYears(5), window));

        Assert.Equal(
            double.PositiveInfinity,
            OfflineExpiry.DaysLeft(Installed, Installed, Installed.AddYears(5), window));
    }

    [Fact]
    public void DaysLeftCountsDown()
    {
        var last = Installed.AddDays(10);

        Assert.Equal(Window - 20, OfflineExpiry.DaysLeft(last, Installed, last.AddDays(20), Window), 3);
        Assert.True(OfflineExpiry.DaysLeft(last, Installed, last.AddDays(Window + 5), Window) < 0);
    }

    [Fact]
    public void DefaultWindowIsGenerous()
    {
        /*
         * שישים יום, ובכוונה. חלון קצר היה הופך כל חופשה או מחשב
         * שהיה במגירה לשחרור אכיפה; חלון ארוך הופך שתיקה לבולטת,
         * וההורה ממילא מקבל התראה על מחשב ששותק הרבה קודם.
         */
        Assert.Equal(60, new EnforcementPolicy().MaxOfflineDays);
    }
}
