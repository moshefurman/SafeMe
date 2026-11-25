using FilterPlus.Core.Abstractions;
using FilterPlus.Core.Models;

namespace FilterPlus.Service.State;

/// <summary>
/// מקור האמת היחיד לסטטוס הסוכן. כל הרכיבים קוראים וכותבים דרכו,
/// כדי ש-TrayApp והפעימה לשרת יראו תמיד את אותה תמונת מצב.
/// </summary>
public sealed class AgentState : IAgentStateProvider
{
    private readonly object _sync = new();
    private readonly DateTimeOffset _startedUtc = DateTimeOffset.UtcNow;

    private StatusSnapshot _snapshot = new()
    {
        Status = SecurityStatus.Unknown,
        Headline = "מאתחל את סוכן FilterPlus..."
    };

    public event Action<StatusSnapshot>? Changed;

    public StatusSnapshot Current
    {
        get
        {
            lock (_sync)
            {
                _snapshot.UptimeSeconds = (long)(DateTimeOffset.UtcNow - _startedUtc).TotalSeconds;
                return _snapshot;
            }
        }
    }

    public void Update(Action<StatusSnapshot> mutate)
    {
        StatusSnapshot updated;

        lock (_sync)
        {
            mutate(_snapshot);
            _snapshot.UptimeSeconds = (long)(DateTimeOffset.UtcNow - _startedUtc).TotalSeconds;
            updated = _snapshot;
        }

        // ההודעה נשלחת מחוץ לנעילה כדי שמנוי איטי לא יחסום כותבים אחרים
        Changed?.Invoke(updated);
    }
}
