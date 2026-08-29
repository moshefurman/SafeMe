using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using SafeMe.Core;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;
using SafeMe.Core.Security;

namespace SafeMe.Service.State;

public enum PolicyRejection
{
    Accepted = 0,
    BadSignature = 1,
    OlderVersion = 2,
    BelowFloor = 3,
    Malformed = 4
}

public sealed record PolicyAcceptance
{
    public PolicyRejection Status { get; init; }
    public string Message { get; init; } = "";
    public IReadOnlyList<string> LooseningReasons { get; init; } = [];

    /// <summary>המדיניות התקבלה, אך צירים שניסו להקל הועלו לרצפה.</summary>
    public bool ClampedToFloor { get; init; }

    public bool Accepted => Status == PolicyRejection.Accepted;
}

/// <summary>
/// שומר ומאמת את חבילת המדיניות.
///
/// שלוש שכבות הגנה, לפי הסדר:
///   1. חתימה — על הבתים שהגיעו, לא על JSON שנבנה מחדש (ראה 5.2 באפיון).
///   2. גרסה — מדיניות ישנה יותר נדחית, כדי למנוע החזרת מדיניות מקלה.
///   3. רצפה — מדיניות שנמוכה מרצפת המכשיר **מוצמדת** אליה: היא נכנסת,
///      והצירים שניסו להקל מועלים בחזרה. רק היתר הקלה חתום מוריד את
///      הרצפה עצמה (ראה 3.2.3).
///
/// שכבה 3 היא מה שהופך את המחגר לאמיתי: שרת פרוץ יכול לחתום על מה
/// שירצה, אך לא יכול לגרום למכשיר להקל בלי היתר נפרד וחתום.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PolicyStore
{
    private readonly ILogger<PolicyStore> _log;
    private readonly object _sync = new();

    private PolicyBundle _current = PolicyBundle.CreateDefault();
    private PolicyFloorSpec _floor = PolicyFloorSpec.Default;
    private readonly List<string> _usedGrantNonces = new();

    public PolicyStore(ILogger<PolicyStore> log)
    {
        _log = log;
        LoadFromDisk();
    }

    public PolicyBundle Current
    {
        get { lock (_sync) return _current; }
    }

    public PolicyFloorSpec Floor
    {
        get { lock (_sync) return _floor; }
    }

    // ---------------------------------------------------------------- רצפה

    /// <summary>
    /// קובע את רצפת המכשיר מתוך מעטפה חתומה שהתקבלה ברישום.
    /// הרצפה נשמרת מוצפנת, ומכאן והלאה כל מדיניות נמדדת מולה.
    /// </summary>
    public bool SetFloorFromEnvelope(SignedEnvelope envelope, string? publicKeyPem, string hwid)
    {
        var result = SignedEnvelopeReader.Verify<PolicyFloorEnvelope>(envelope, publicKeyPem);

        if (!result.Ok || result.Value is null)
        {
            _log.LogError("רצפת המדיניות נדחתה: {Message}", result.Message);
            return false;
        }

        // רצפה שהונפקה למכשיר אחר אינה תקפה כאן
        if (!string.Equals(result.Value.Hwid, hwid, StringComparison.OrdinalIgnoreCase))
        {
            _log.LogError("רצפת המדיניות הונפקה עבור מכשיר אחר ולכן נדחתה.");
            return false;
        }

        lock (_sync)
        {
            _floor = result.Value.Floor;
        }

        SaveFloorToDisk();
        _log.LogInformation(
            "רצפת מדיניות נקבעה: מצב {Mode}, פעולה באדום {Action}, סף ירוק {Green}.",
            _floor.Mode, _floor.OnRedAction, _floor.MinScoreForGreen);

        return true;
    }

    /// <summary>
    /// מוריד את הרצפה לפי היתר חתום. זו הפעולה היחידה שמרפה את המחגר,
    /// ולכן היא נבדקת פעמיים: חתימה במפתח ההקלות, ואז תוקף מול המכשיר.
    /// </summary>
    public bool ApplyLooseningGrant(
        SignedEnvelope envelope,
        string? looseningKeyPem,
        string? policyKeyPem,
        string hwid)
    {
        // הסוכן אוכף את ההפרדה בעצמו, ולא סומך על כך שהשרת אכף אותה.
        // הכלל עצמו יושב ב-Core, ליד שאר אימות ההיתר, כדי שיהיה נבדק.
        var separation = LooseningGrantValidator.CheckKeySeparation(looseningKeyPem, policyKeyPem);

        if (!separation.Ok)
        {
            _log.LogError("היתר ההקלה נדחה: {Message}", separation.Message);
            return false;
        }

        var verified = SignedEnvelopeReader.Verify<LooseningGrant>(envelope, looseningKeyPem);

        if (!verified.Ok || verified.Value is null)
        {
            _log.LogError("היתר ההקלה נדחה: {Message}", verified.Message);
            return false;
        }

        lock (_sync)
        {
            var check = LooseningGrantValidator.Validate(
                verified.Value, hwid, _floor, _usedGrantNonces);

            if (!check.Ok)
            {
                _log.LogError("היתר ההקלה נדחה: {Message}", check.Message);
                return false;
            }

            _floor = verified.Value.ToFloor;
            _usedGrantNonces.Add(verified.Value.Nonce);

            // שמירת היסטוריה מוגבלת: די בה למניעת שימוש חוזר
            if (_usedGrantNonces.Count > 50)
                _usedGrantNonces.RemoveRange(0, _usedGrantNonces.Count - 50);
        }

        SaveFloorToDisk();

        _log.LogWarning(
            "רצפת המדיניות הורדה בהיתר חתום מאת {Approver}. סיבה: {Reason}",
            verified.Value.ApprovedBy ?? "לא צוין", verified.Value.Reason ?? "לא צוינה");

        return true;
    }

    // ---------------------------------------------------------------- מדיניות

    /// <summary>
    /// מקבל מדיניות חדשה ממעטפה חתומה. מחזיר את סיבת הדחייה אם נדחתה,
    /// ובמקרה כזה המדיניות הקיימת נשארת בתוקף.
    /// </summary>
    public PolicyAcceptance AcceptEnvelope(SignedEnvelope envelope, string? publicKeyPem)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        var verified = SignedEnvelopeReader.Verify<PolicyBundle>(envelope, publicKeyPem);

        if (!verified.Ok || verified.Value is null)
        {
            _log.LogError("חתימת המדיניות נדחתה: {Message}", verified.Message);

            return new PolicyAcceptance
            {
                Status = verified.Status == EnvelopeVerification.MalformedContent
                    ? PolicyRejection.Malformed
                    : PolicyRejection.BadSignature,
                Message = verified.Message
            };
        }

        return Accept(verified.Value);
    }

    /// <summary>מחיל מדיניות שכבר אומתה קריפטוגרפית.</summary>
    public PolicyAcceptance Accept(PolicyBundle policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        ClampResult clamped;

        lock (_sync)
        {
            if (policy.Version < _current.Version)
            {
                _log.LogWarning(
                    "התקבלה מדיניות ישנה יותר ({New} מול {Current}) והיא נדחתה.",
                    policy.Version, _current.Version);

                return new PolicyAcceptance
                {
                    Status = PolicyRejection.OlderVersion,
                    Message = $"גרסה {policy.Version} ישנה מהגרסה הפעילה {_current.Version}."
                };
            }

            /*
             * המחגר: גם מדיניות חתומה כדין אינה מורידה את האכיפה מתחת
             * לרצפה. מה שהיא כן עושה הוא להיכנס — הצירים שניסו להקל
             * מועלים בחזרה, והשאר מוחל.
             *
             * קודם החבילה כולה נדחתה, וזה היה שגוי: היא נושאת גם את
             * כללי זיהוי הספקים, ובלעדיהם המכשיר אינו מזהה אף ספק
             * ומדווח "לא מסונן" על מחשב מסונן. התוצאה הייתה מבוי סתום
             * שהיציאה היחידה ממנו היא התקנה מחדש.
             */
            clamped = PolicyFloorClamp.Apply(policy, _floor);

            // אחרי ההצמדה הרצפה חייבת להתקיים. אם לא — נותר ציר שאיננו
            // יודעים להעלות, וכניסה בכל זאת הייתה הקלה שקטה.
            var delta = StrictnessComparer.CheckAgainstFloor(
                _floor.ToStrictness(), PolicyStrictness.FromPolicy(clamped.Policy));

            if (delta.IsLoosening)
            {
                _log.LogError(
                    "מדיניות גרסה {Version} נדחתה: היא מקלה מתחת לרצפת המכשיר גם אחרי הצמדה. {Reasons}",
                    policy.Version, string.Join(" · ", delta.Reasons));

                return new PolicyAcceptance
                {
                    Status = PolicyRejection.BelowFloor,
                    Message = "המדיניות מקלה מתחת לרצפת המכשיר ונדחתה.",
                    LooseningReasons = delta.Reasons
                };
            }

            _current = clamped.Policy;
        }

        SavePolicyToDisk(clamped.Policy);

        if (clamped.WasClamped)
        {
            _log.LogWarning(
                "מדיניות גרסה {Version} הוחלה והוצמדה לרצפת המכשיר. {Raised}",
                clamped.Policy.Version, string.Join(" · ", clamped.Raised));
        }
        else
        {
            _log.LogInformation("מדיניות גרסה {Version} הוחלה.", clamped.Policy.Version);
        }

        return new PolicyAcceptance
        {
            Status = PolicyRejection.Accepted,
            Message = clamped.WasClamped
                ? "המדיניות הוחלה, והאכיפה נשמרה ברמת הרצפה."
                : "המדיניות הוחלה.",
            ClampedToFloor = clamped.WasClamped,
            LooseningReasons = clamped.Raised
        };
    }

    /// <summary>
    /// האם המדיניות פגה. חשוב להבין את המשמעות: מדיניות פגה **אינה**
    /// מרפה את האכיפה. היא רק מסומנת כישנה ומדווחת לשרת. מכשיר שמנותק
    /// חודשיים ממשיך לאכוף את מה שידע, וזו התנהגות מכוונת.
    /// </summary>
    public bool IsStale
    {
        get { lock (_sync) return _current.IsExpired; }
    }

    // ---------------------------------------------------------------- דיסק

    private sealed class FloorState
    {
        public PolicyFloorSpec Floor { get; set; } = new();
        public List<string> UsedGrantNonces { get; set; } = new();
    }

    private static string FloorPath => Path.Combine(SafeMePaths.StateDir, "floor.dat");

    private void LoadFromDisk()
    {
        try
        {
            if (File.Exists(SafeMePaths.PolicyFile))
            {
                var json = File.ReadAllText(SafeMePaths.PolicyFile, Encoding.UTF8);
                var policy = SafeMeJson.Deserialize<PolicyBundle>(json);

                if (policy is not null)
                {
                    _current = policy;
                    _log.LogInformation("נטענה מדיניות שמורה, גרסה {Version}.", policy.Version);
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "טעינת המדיניות השמורה נכשלה. נעשה שימוש בברירת המחדל.");
        }

        // הרצפה מוצפנת: היא קובעת מה מותר, ולכן אסור שתהיה ניתנת לעריכה
        var floorState = SecureStore.Read<FloorState>(FloorPath);

        if (floorState is not null)
        {
            _floor = floorState.Floor;
            _usedGrantNonces.AddRange(floorState.UsedGrantNonces);

            _log.LogInformation("נטענה רצפת מדיניות שמורה: מצב {Mode}.", _floor.Mode);
        }
        else if (SecureStore.IsCorrupted(FloorPath))
        {
            // Fail-Secure: רצפה פגומה מוחלפת בברירת המחדל המחמירה,
            // ולא בשום דבר מקל יותר
            _log.LogWarning("קובץ הרצפה פגום. נעשה שימוש ברצפת ברירת המחדל המחמירה.");
            _floor = PolicyFloorSpec.Default;
        }
    }

    private void SaveFloorToDisk()
    {
        try
        {
            lock (_sync)
            {
                SecureStore.Write(FloorPath, new FloorState
                {
                    Floor = _floor,
                    UsedGrantNonces = _usedGrantNonces
                });
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "שמירת רצפת המדיניות נכשלה.");
        }
    }

    private void SavePolicyToDisk(PolicyBundle policy)
    {
        try
        {
            Directory.CreateDirectory(SafeMePaths.StateDir);

            var temp = SafeMePaths.PolicyFile + ".tmp";

            File.WriteAllText(temp, SafeMeJson.Serialize(policy), Encoding.UTF8);
            File.Move(temp, SafeMePaths.PolicyFile, overwrite: true);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "שמירת המדיניות לדיסק נכשלה.");
        }
    }
}
