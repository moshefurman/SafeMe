using FilterPlus.Core.Models;
using FilterPlus.Core.Security;

namespace FilterPlus.Tests;

/// <summary>
/// הניסיון הראשון על מחשב רשום.
///
/// המצב הזה נשבר בשטח: קובץ מצב ההסרה נוצר רק בשימוש הראשון, בעוד
/// שהבדיקה "האם היה אי פעם" הסתמכה על device.dat שנוצר ברישום. כל
/// ניסיון הסרה ראשון נראה כמחיקת קובץ, ולכן נעל את עצמו — והמשתמש
/// ראה "ניסיונות הסרה שגויים" בלי שהיה ולו ניסיון אחד.
/// </summary>
public sealed class UninstallFirstUseTests
{
    private sealed class FakeStore : IUninstallStateStore
    {
        private UninstallAttemptState? _state;

        /// <summary>מדמה את הדגל שנשמר במצב המחשב.</summary>
        public bool Initialized { get; private set; }

        public int TamperReports { get; private set; }

        public UninstallAttemptState Load()
        {
            if (_state is not null) return _state;

            // הפעם הראשונה: מצב נקי, לא נעול.
            if (!Initialized)
            {
                Initialized = true;
                return _state = new UninstallAttemptState { LastSeenUtc = DateTimeOffset.UtcNow };
            }

            // הקובץ נמחק אחרי שכבר היה. זו חבלה.
            TamperReports++;

            return _state = new UninstallAttemptState
            {
                LastSeenUtc = DateTimeOffset.UtcNow,
                LockoutUntilUtc = DateTimeOffset.UtcNow.AddMinutes(15),
                LockoutCount = 1,
            };
        }

        public void Save(UninstallAttemptState state) => _state = state;

        public void ReportTamper(TamperKind kind, string detail) => TamperReports++;

        /// <summary>מדמה מחיקה של הקובץ בזמן שהדגל נשאר דלוק.</summary>
        public void SimulateDeletion() => _state = null;
    }

    [Fact]
    public void FirstAttemptOnEnrolledMachineIsNotTampering()
    {
        var store = new FakeStore();
        var guard = new UninstallAttemptGuard(store);

        var (challenge, rejection) = guard.IssueChallenge("HWID-1", UninstallKeyMode.Rsa);

        Assert.NotNull(challenge);
        Assert.Null(rejection);
        Assert.Equal(0, store.TamperReports);
    }

    [Fact]
    public void DeletingTheFileAfterwardsStillLocks()
    {
        var store = new FakeStore();
        var guard = new UninstallAttemptGuard(store);

        guard.IssueChallenge("HWID-1", UninstallKeyMode.Rsa);

        // fail-secure נשמר: מה שנשבר היה רק ההבחנה בין "עוד לא היה"
        // לבין "נמחק", ולא ההגנה עצמה.
        store.SimulateDeletion();

        var (challenge, rejection) = guard.IssueChallenge("HWID-1", UninstallKeyMode.Rsa);

        Assert.Null(challenge);
        Assert.NotNull(rejection);
        Assert.True(store.TamperReports > 0);
    }
}
