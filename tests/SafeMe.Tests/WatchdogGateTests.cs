using SafeMe.Core.Watchdog;

namespace SafeMe.Tests;

/// <summary>
/// מתי השומר מחיה שירות שנעצר.
///
/// זהו הפער שההגנה העצמית לא כיסתה: sc failure מחזיר שירות שקרס,
/// אך לא שירות שנעצר בפקודה. עצירה נקייה אינה כשל, ומבחינת Windows
/// לא קרה דבר — ולכן מי שמריץ sc stop השאיר את ההגנה מכובה עד
/// שהמשימה המתוזמנת התעוררה, רבע שעה אחר כך.
///
/// שני הצירופים שקשה לייצר על מכונה אמיתית נבדקים דווקא כאן:
/// עצירה בזמן עדכון, ולולאת הפעלה כושלת.
/// </summary>
public sealed class WatchdogGateTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RunningNeedsNothing()
    {
        var decision = WatchdogGate.Decide(ServiceState.Running, Now, null);

        Assert.Equal(WatchAction.None, decision.Action);
    }

    /// <summary>הליבה: עצירה מכוונת מוחזרת, ולא רק קריסה.</summary>
    [Fact]
    public void StoppedIsRestarted()
    {
        var decision = WatchdogGate.Decide(ServiceState.Stopped, Now, null);

        Assert.Equal(WatchAction.Start, decision.Action);
    }

    /// <summary>
    /// מצב שלא הצלחנו לברר אינו נחשב עצור.
    ///
    /// הפעלה עיוורת יכולה להתנגש בעצירה מכוונת שבאמצע, והספק מוכרע
    /// לטובת אי-פעולה — כי הצד השני מייצר לולאה בין השומר למתקין.
    /// </summary>
    [Fact]
    public void UnknownDoesNothing()
    {
        var decision = WatchdogGate.Decide(ServiceState.Unknown, Now, null);

        Assert.Equal(WatchAction.None, decision.Action);
    }

    /// <summary>
    /// שירות שאינו רשום כלל אינו בעיה שהפעלה פותרת.
    ///
    /// זה מצב אחר לגמרי: מישהו הסיר את השירות, ולא עצר אותו. ניסיון
    /// הפעלה ייכשל לנצח, ולכן הוא מדווח במקום להתבצע.
    /// </summary>
    [Fact]
    public void MissingIsReportedNotStarted()
    {
        var decision = WatchdogGate.Decide(ServiceState.Missing, Now, null);

        Assert.Equal(WatchAction.ReportMissing, decision.Action);
    }

    [Fact]
    public void RepeatedAttemptsBackOff()
    {
        var justTried = Now - TimeSpan.FromSeconds(1);

        var decision = WatchdogGate.Decide(ServiceState.Stopped, Now, justTried);

        Assert.Equal(WatchAction.Backoff, decision.Action);
    }

    [Fact]
    public void AfterTheBackoffItTriesAgain()
    {
        var older = Now - WatchdogGate.Backoff - TimeSpan.FromSeconds(1);

        var decision = WatchdogGate.Decide(ServiceState.Stopped, Now, older);

        Assert.Equal(WatchAction.Start, decision.Action);
    }

    /// <summary>
    /// הצירוף שהיה הופך את השומר למזיק.
    ///
    /// המתקין עוצר את השירות כדי להחליף את קבציו. שומר שיחזיר אותו
    /// באותו רגע יחזיק את הקבצים נעולים, העדכון ייכשל, והוא יופעל
    /// שוב — ולא ייגמר.
    /// </summary>
    [Fact]
    public void DoesNotFightTheInstaller()
    {
        var decision = WatchdogGate.Decide(
            ServiceState.Stopped, Now, null, updateInProgress: true);

        Assert.Equal(WatchAction.None, decision.Action);
    }

    /// <summary>אבל שירות שרץ בזמן עדכון אינו מעניין את השומר בכלל.</summary>
    [Fact]
    public void UpdateDoesNotMaskARunningService()
    {
        var decision = WatchdogGate.Decide(
            ServiceState.Running, Now, null, updateInProgress: true);

        Assert.Equal(WatchAction.None, decision.Action);
    }

    [Fact]
    public void EveryActionExplainsItself()
    {
        foreach (var state in new[] { ServiceState.Stopped, ServiceState.Missing })
        {
            var decision = WatchdogGate.Decide(state, Now, null);

            Assert.False(string.IsNullOrWhiteSpace(decision.Reason));
        }
    }
}
