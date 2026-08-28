using SafeMe.Core.Audit;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;

using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// ההבחנה שנעלה מחשב אמיתי, פעמיים.
///
/// "בדקתי ולא מצאתי ספק" ו"לא הצלחתי לבדוק" הם שני דברים שונים
/// לגמרי. שניהם נראו זהים בקוד, ושניהם החזירו Unfiltered — ומכיוון
/// שהמדיניות נועלת על Unfiltered, מחשב בלי רשת ננעל, ואז לא יכול
/// היה לבדוק שוב כי הבדיקה עצמה זקוקה לרשת.
///
/// מלכוד סגור: החסימה מנעה את הבדיקה שהייתה משחררת אותה.
/// </summary>
public class DetectionFailureTests
{
    private static EnforcementPolicy Policy() => new()
    {
        MinScoreForGreen = 85,
        MinScoreForYellow = 60,
        OnRedAction = RedAction.Lockout,
    };

    [Fact]
    public void A_detection_that_could_not_run_is_unknown_not_unfiltered()
    {
        var detection = new ProviderDetection
        {
            Trust = TrustLevel.None,
            DetectionRan = false,
        };

        var status = ScoreCalculator.ResolveStatus(0, detection, Policy(), lockoutActive: false);

        Assert.Equal(SecurityStatus.Unknown, status);
        Assert.NotEqual(SecurityStatus.Unfiltered, status);
    }

    [Fact]
    public void A_detection_that_ran_and_found_nothing_is_unfiltered()
    {
        // הצד השני של אותה הבחנה: כשבאמת בדקנו, החסימה מוצדקת.
        var detection = new ProviderDetection
        {
            Trust = TrustLevel.None,
            PublicIp = "203.0.113.9",
            DetectionRan = true,
        };

        var status = ScoreCalculator.ResolveStatus(0, detection, Policy(), lockoutActive: false);

        Assert.Equal(SecurityStatus.Unfiltered, status);
    }

    [Fact]
    public void A_recognised_provider_is_still_safe()
    {
        var detection = new ProviderDetection
        {
            ProviderId = "rimon",
            DisplayName = "רימון",
            Trust = TrustLevel.High,
            IpRangeMatch = true,
            PublicIp = "213.151.63.84",
            DetectionRan = true,
        };

        var status = ScoreCalculator.ResolveStatus(95, detection, Policy(), lockoutActive: false);

        Assert.Equal(SecurityStatus.Safe, status);
    }

    /// <summary>
    /// ברירת המחדל היא שהבדיקה כן רצה.
    ///
    /// כל קוד קיים שבונה ProviderDetection בלי לחשוב על השדה הזה
    /// ממשיך להתנהג כמו קודם. שינוי ברירת המחדל היה משתיק חסימות
    /// אמיתיות בכל מקום שלא עודכן.
    /// </summary>
    [Fact]
    public void Detection_is_assumed_to_have_run_unless_stated()
    {
        Assert.True(new ProviderDetection().DetectionRan);
    }

    /// <summary>
    /// Unknown אינו מצדיק חסימה בשום מדיניות.
    ///
    /// זו השורה התחתונה של כל התיקון: מה שהמחשב אינו יודע אינו
    /// עילה לנתק אותו.
    /// </summary>
    [Theory]
    [InlineData(RedAction.None)]
    [InlineData(RedAction.Warn)]
    [InlineData(RedAction.Lockout)]
    public void Unknown_never_becomes_unfiltered(RedAction action)
    {
        var policy = Policy();
        policy.OnRedAction = action;

        var status = ScoreCalculator.ResolveStatus(
            0,
            new ProviderDetection { DetectionRan = false },
            policy,
            lockoutActive: false);

        Assert.Equal(SecurityStatus.Unknown, status);
    }
}
