using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using FilterPlus.Core;
using FilterPlus.Core.Models;
using FilterPlus.Service.State;

namespace FilterPlus.Service.Workers;

/// <summary>
/// תור אירועי חבלה. אירועים נשמרים לדיסק מיד, כדי שאירוע שנוצר רגע לפני
/// שהשירות נהרג עדיין יגיע לשרת בהפעלה הבאה.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventQueue
{
    /// <summary>תקרת גודל התור, כדי שמחשב מנותק לא ימלא את הדיסק.</summary>
    private const int MaxEvents = 500;

    private readonly ILogger<EventQueue> _log;
    private readonly ConcurrentQueue<TamperEvent> _pending = new();
    private readonly object _fileSync = new();

    public EventQueue(ILogger<EventQueue> log)
    {
        _log = log;
        LoadFromDisk();
    }

    public int Count => _pending.Count;

    public void Enqueue(TamperEvent tamperEvent)
    {
        if (_pending.Count >= MaxEvents)
        {
            _pending.TryDequeue(out _);
            _log.LogWarning("תור האירועים מלא. האירוע הישן ביותר הושמט.");
        }

        _pending.Enqueue(tamperEvent);
        AppendToDisk(tamperEvent);

        _log.LogInformation("אירוע {Kind} נרשם: {Detail}", tamperEvent.Kind, tamperEvent.Detail);
    }

    /// <summary>שולף את כל האירועים הממתינים לצורך שליחה.</summary>
    public List<TamperEvent> DrainAll()
    {
        var drained = new List<TamperEvent>();

        while (_pending.TryDequeue(out var item))
            drained.Add(item);

        return drained;
    }

    /// <summary>מחזיר אירועים לתור כאשר השליחה נכשלה.</summary>
    public void Requeue(IEnumerable<TamperEvent> events)
    {
        foreach (var item in events)
            _pending.Enqueue(item);
    }

    /// <summary>מנקה את קובץ התור לאחר שליחה מוצלחת.</summary>
    public void ClearDisk()
    {
        lock (_fileSync)
        {
            try
            {
                if (File.Exists(FilterPlusPaths.EventQueueFile))
                    File.Delete(FilterPlusPaths.EventQueueFile);
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "ניקוי קובץ תור האירועים נכשל.");
            }
        }
    }

    private void AppendToDisk(TamperEvent tamperEvent)
    {
        lock (_fileSync)
        {
            try
            {
                Directory.CreateDirectory(FilterPlusPaths.Queue);
                File.AppendAllText(FilterPlusPaths.EventQueueFile,
                    FilterPlusJson.Serialize(tamperEvent) + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "כתיבת אירוע לתור בדיסק נכשלה.");
            }
        }
    }

    private void LoadFromDisk()
    {
        lock (_fileSync)
        {
            try
            {
                if (!File.Exists(FilterPlusPaths.EventQueueFile)) return;

                foreach (var line in File.ReadLines(FilterPlusPaths.EventQueueFile, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    if (FilterPlusJson.TryDeserialize<TamperEvent>(line, out var item) && item is not null)
                        _pending.Enqueue(item);
                }

                _log.LogInformation("נטענו {Count} אירועים ממתינים מהתור בדיסק.", _pending.Count);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "טעינת תור האירועים נכשלה.");
            }
        }
    }
}
