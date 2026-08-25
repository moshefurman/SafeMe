using SafeMe.Core.Models;

namespace SafeMe.Core.Security;

/// <summary>מצב מתמשך של תהליך ההסרה: אתגר פתוח, ניסיונות כושלים ונעילות.</summary>
public sealed class UninstallAttemptState
{
    /// <summary>מספר הכשלונות מאז ההצלחה או הנעילה האחרונה.</summary>
    public int FailedAttempts { get; set; }

    /// <summary>כמה פעמים כבר ננעל, לצורך הסלמת משך הנעילה.</summary>
    public int LockoutCount { get; set; }

    public DateTimeOffset? LockoutUntilUtc { get; set; }

    /// <summary>
    /// עוגן זמן מונוטוני. נשמר בכל גישה ומונע קיצור נעילה על ידי הזזת שעון המערכת אחורה.
    /// </summary>
    public DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>האתגר הפתוח שהונפק, בייצוג תצוגה.</summary>
    public string? PendingChallenge { get; set; }

    public DateTimeOffset? PendingIssuedUtc { get; set; }

    /// <summary>Nonce-ים שכבר נוצלו בהצלחה (hex), למניעת שימוש חוזר.</summary>
    public List<string> UsedNonces { get; set; } = new();

    /// <summary>אסימון ההסרה שהונפק לאחר אימות מוצלח.</summary>
    public string? GrantedToken { get; set; }

    public DateTimeOffset? GrantedUtc { get; set; }
}

/// <summary>אחסון מוגן של מצב ההסרה. המימוש בשירות מצפין ב-DPAPI ומחיל ACL.</summary>
public interface IUninstallStateStore
{
    UninstallAttemptState Load();
    void Save(UninstallAttemptState state);

    /// <summary>
    /// מדווח שהמצב השמור נעלם או נפגם. המדיניות היא Fail-Secure:
    /// מצב חסר נחשב לניסיון חבלה ומאתחל למצב נעול.
    /// </summary>
    void ReportTamper(TamperKind kind, string detail);
}

/// <summary>
/// שער האכיפה של תהליך ההסרה: הנפקת אתגר, הגבלת קצב ואימות.
/// כל הלוגיקה מרוכזת כאן כדי שתהיה בת-בדיקה ללא תלות במערכת ההפעלה.
/// </summary>
public sealed class UninstallAttemptGuard
{
    private readonly IUninstallStateStore _store;
    private readonly object _sync = new();

    /// <summary>מספר הניסיונות המותרים לפני נעילה.</summary>
    public int MaxAttempts { get; init; } = 3;

    /// <summary>משך הנעילה הבסיסי. כל נעילה נוספת מכפילה אותו.</summary>
    public TimeSpan BaseLockout { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>תקרת משך הנעילה.</summary>
    public TimeSpan MaxLockout { get; init; } = TimeSpan.FromHours(4);

    /// <summary>משך התוקף של אתגר שהונפק.</summary>
    public TimeSpan ChallengeValidity { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>כמה Nonce-ים מנוצלים לשמור בהיסטוריה.</summary>
    public int UsedNonceHistory { get; init; } = 50;

    public UninstallAttemptGuard(IUninstallStateStore store) => _store = store;

    /// <summary>מנפיק אתגר חדש, אלא אם המכשיר נעול כרגע.</summary>
    public (UninstallChallenge? Challenge, ChallengeValidationResult? Rejection) IssueChallenge(
        string hwid, UninstallKeyMode mode, DateTimeOffset? nowUtc = null)
    {
        lock (_sync)
        {
            var state = _store.Load();
            var now = Advance(state, nowUtc ?? DateTimeOffset.UtcNow);

            if (IsLocked(state, now, out var until))
            {
                _store.Save(state);

                return (null, ChallengeValidationResult.Fail(
                    ChallengeValidation.RateLimited,
                    $"המכשיר נעול עקב ניסיונות שגויים. נסה שוב בעוד {Remaining(until!.Value, now)}.",
                    0, until));
            }

            var challenge = UninstallChallenge.Create(hwid, mode);

            state.PendingChallenge = challenge.ToDisplayString();
            state.PendingIssuedUtc = challenge.IssuedUtc;
            _store.Save(state);

            return (challenge, null);
        }
    }

    /// <summary>מאמת קוד תגובה מול האתגר הפתוח, כולל אכיפת הגבלת קצב.</summary>
    public ChallengeValidationResult Verify(
        string challengeText,
        string responseText,
        string hwid,
        UninstallKeyMode mode,
        string? uninstallPublicKeyPem,
        string? policyPublicKeyPem,
        byte[]? deviceSecret,
        DateTimeOffset? nowUtc = null)
    {
        lock (_sync)
        {
            var state = _store.Load();
            var now = Advance(state, nowUtc ?? DateTimeOffset.UtcNow);

            if (IsLocked(state, now, out var until))
            {
                _store.Save(state);

                return ChallengeValidationResult.Fail(
                    ChallengeValidation.RateLimited,
                    $"המכשיר נעול עקב ניסיונות שגויים. נסה שוב בעוד {Remaining(until!.Value, now)}.",
                    0, until);
            }

            UninstallChallenge? expected = null;

            if (!string.IsNullOrWhiteSpace(state.PendingChallenge))
                UninstallChallenge.TryParse(state.PendingChallenge, out expected, out _);

            var options = new ChallengeValidationOptions
            {
                Hwid = hwid,
                Mode = mode,
                UninstallPublicKeyPem = uninstallPublicKeyPem,
                PolicyPublicKeyPem = policyPublicKeyPem,
                DeviceSecret = deviceSecret,
                Validity = ChallengeValidity,
                ExpectedChallenge = expected,
                UsedNonces = state.UsedNonces
            };

            var result = ChallengeResponseService.Validate(challengeText, responseText, options, now);

            if (result.Granted)
            {
                if (UninstallChallenge.TryParse(challengeText, out var parsed, out _) && parsed is not null)
                {
                    state.UsedNonces.Add(Convert.ToHexString(parsed.Nonce));

                    if (state.UsedNonces.Count > UsedNonceHistory)
                        state.UsedNonces.RemoveRange(0, state.UsedNonces.Count - UsedNonceHistory);

                    state.GrantedToken = ChallengeResponseService.CreateUninstallToken(hwid, parsed);
                    state.GrantedUtc = now;
                }

                state.FailedAttempts = 0;
                state.LockoutCount = 0;
                state.LockoutUntilUtc = null;
                state.PendingChallenge = null;
                state.PendingIssuedUtc = null;
                _store.Save(state);

                return new ChallengeValidationResult
                {
                    Status = ChallengeValidation.Ok,
                    Message = "הקוד אומת בהצלחה. ניתן להמשיך בהסרה."
                };
            }

            // כשלים תקפים בלבד נספרים. קוד אתגר פגום או ששייך למחשב אחר
            // אינו מקדם את המונה, כדי שטעות הקלדה לא תנעל את המשתמש.
            var countsAsAttempt = result.Status is
                ChallengeValidation.BadResponse or
                ChallengeValidation.NonceMismatch or
                ChallengeValidation.AlreadyUsed;

            if (!countsAsAttempt)
            {
                _store.Save(state);
                return result with { AttemptsLeft = MaxAttempts - state.FailedAttempts };
            }

            state.FailedAttempts++;

            if (state.FailedAttempts >= MaxAttempts)
            {
                var duration = ComputeLockout(state.LockoutCount);

                state.LockoutCount++;
                state.LockoutUntilUtc = now + duration;
                state.FailedAttempts = 0;
                state.PendingChallenge = null;
                state.PendingIssuedUtc = null;
                _store.Save(state);

                _store.ReportTamper(TamperKind.UninstallBruteForce,
                    $"נחסם לאחר {MaxAttempts} ניסיונות כושלים. משך הנעילה: {duration}.");

                return ChallengeValidationResult.Fail(
                    ChallengeValidation.RateLimited,
                    $"הוזנו {MaxAttempts} קודים שגויים. המכשיר נעול ל-{(int)duration.TotalMinutes} דקות.",
                    0, state.LockoutUntilUtc);
            }

            _store.Save(state);

            var left = MaxAttempts - state.FailedAttempts;

            return ChallengeValidationResult.Fail(
                result.Status,
                $"{result.Message} נותרו {left} ניסיונות.",
                left);
        }
    }

    /// <summary>מחזיר את מצב הנעילה הנוכחי לתצוגה.</summary>
    public (bool Active, DateTimeOffset? Until) GetLockoutState(DateTimeOffset? nowUtc = null)
    {
        lock (_sync)
        {
            var state = _store.Load();
            var now = Advance(state, nowUtc ?? DateTimeOffset.UtcNow);
            var locked = IsLocked(state, now, out var until);

            _store.Save(state);

            return (locked, until);
        }
    }

    /// <summary>האסימון שהונפק לאחר אימות מוצלח, אם עדיין בתוקף (שעה).</summary>
    public string? GetGrantedToken(DateTimeOffset? nowUtc = null)
    {
        lock (_sync)
        {
            var state = _store.Load();
            var now = nowUtc ?? DateTimeOffset.UtcNow;

            if (state.GrantedToken is null || state.GrantedUtc is null) return null;

            return now - state.GrantedUtc.Value <= TimeSpan.FromHours(1) ? state.GrantedToken : null;
        }
    }

    // ---------------------------------------------------------------- פנימי

    /// <summary>
    /// מקדם את עוגן הזמן המונוטוני. אם שעון המערכת הוזז אחורה, ממשיכים לפי
    /// הזמן האחרון שנראה, כך שנעילה אינה מתקצרת על ידי שינוי השעון.
    /// </summary>
    private static DateTimeOffset Advance(UninstallAttemptState state, DateTimeOffset systemNow)
    {
        var effective = systemNow > state.LastSeenUtc ? systemNow : state.LastSeenUtc;
        state.LastSeenUtc = effective;
        return effective;
    }

    private static bool IsLocked(UninstallAttemptState state, DateTimeOffset now, out DateTimeOffset? until)
    {
        until = state.LockoutUntilUtc;

        if (until is null) return false;
        if (now < until.Value) return true;

        state.LockoutUntilUtc = null;
        until = null;

        return false;
    }

    private TimeSpan ComputeLockout(int previousLockouts)
    {
        var factor = Math.Min(previousLockouts, 8); // תקרה למניעת גלישה
        var ticks = BaseLockout.Ticks * (1L << factor);

        return ticks > MaxLockout.Ticks || ticks < 0 ? MaxLockout : TimeSpan.FromTicks(ticks);
    }

    private static string Remaining(DateTimeOffset until, DateTimeOffset now)
    {
        var span = until - now;

        if (span.TotalMinutes < 1) return "פחות מדקה";
        if (span.TotalHours < 1) return $"{(int)span.TotalMinutes} דקות";

        return $"{(int)span.TotalHours} שעות ו-{span.Minutes} דקות";
    }
}
