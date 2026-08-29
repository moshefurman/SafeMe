using SafeMe.Core.Models;
using SafeMe.Core.Policy;

using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// המחגר על רצפת המחשב.
///
/// הרצפה היא ההבטחה שהמחשב נושא איתו: אף מדיניות, ואף רישום חוזר,
/// לא יורידו אותו מתחתיה. הבדיקות כאן שומרות על הכיוון — החמרה
/// עוברת, הרפיה נעצרת.
///
/// הצד ה-C# הוא זה שאוכף בפועל: השרת יכול לשלוח מה שירצה, והסוכן
/// דוחה. זו הסיבה שהמחגר קיים בשני הצדדים ולא באחד.
/// </summary>
public class PolicyFloorCompareTests
{
    private static PolicyStrictness Floor(EnforcementMode mode, RedAction action, int green = 85)
        => PolicyStrictness.Floor(mode, action, green, 60, new List<string>());

    private static PolicyStrictness Offered(EnforcementMode mode, RedAction action, int green = 85)
        => PolicyStrictness.FromPolicy(new PolicyBundle
        {
            Enforcement = new EnforcementPolicy
            {
                Mode = mode,
                OnRedAction = action,
                MinScoreForGreen = green,
                MinScoreForYellow = 60,
            },
        });

    [Fact]
    public void An_equal_policy_is_accepted()
    {
        var delta = StrictnessComparer.CheckAgainstFloor(
            Floor(EnforcementMode.Monitor, RedAction.Warn),
            Offered(EnforcementMode.Monitor, RedAction.Warn));

        Assert.Empty(delta.Reasons);
    }

    [Fact]
    public void A_stricter_policy_is_accepted()
    {
        var delta = StrictnessComparer.CheckAgainstFloor(
            Floor(EnforcementMode.Monitor, RedAction.Warn),
            Offered(EnforcementMode.Enforce, RedAction.Lockout));

        Assert.Empty(delta.Reasons);
    }

    /// <summary>
    /// זה בדיוק מה שקרה בשטח: הרצפה נשארה enforce/lockout מאסימון
    /// ישן, והתבנית ירדה ל-monitor/warn. המחשב דחה אותה בכל פעימה,
    /// ואיתה נפלו גם כללי זיהוי הספקים.
    /// </summary>
    [Fact]
    public void A_looser_policy_is_refused_and_says_why()
    {
        var delta = StrictnessComparer.CheckAgainstFloor(
            Floor(EnforcementMode.Enforce, RedAction.Lockout),
            Offered(EnforcementMode.Monitor, RedAction.Warn));

        Assert.NotEmpty(delta.Reasons);
        Assert.Contains(delta.Reasons, r => r.Contains("מצב האכיפה"));
        Assert.Contains(delta.Reasons, r => r.Contains("במצב אדום"));
    }

    [Fact]
    public void Lowering_only_the_red_action_is_still_a_loosening()
    {
        var delta = StrictnessComparer.CheckAgainstFloor(
            Floor(EnforcementMode.Enforce, RedAction.Lockout),
            Offered(EnforcementMode.Enforce, RedAction.Warn));

        Assert.Single(delta.Reasons);
    }

    [Fact]
    public void Lowering_a_score_threshold_is_a_loosening()
    {
        // סף נמוך יותר פירושו שפחות נדרש כדי להיחשב תקין
        var delta = StrictnessComparer.CheckAgainstFloor(
            Floor(EnforcementMode.Monitor, RedAction.Warn, green: 85),
            Offered(EnforcementMode.Monitor, RedAction.Warn, green: 50));

        Assert.NotEmpty(delta.Reasons);
    }
}
