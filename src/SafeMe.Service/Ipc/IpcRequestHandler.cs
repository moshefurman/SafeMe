using System.Reflection;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SafeMe.Service.Net;
using Microsoft.Extensions.Options;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Ipc;
using SafeMe.Core;
using SafeMe.Core.Models;
using SafeMe.Core.Security;
using SafeMe.Service.Audit;
using SafeMe.Service.State;
using SafeMe.Service.Workers;

namespace SafeMe.Service.Ipc;

/// <summary>
/// מטפל בבקשות ה-IPC. זהו המקום היחיד שבו מתבצע אימות קוד ההסרה,
/// כדי שהחלפה או ניפוי של ממשק המשתמש לא יעקפו את הבדיקה.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpcRequestHandler
{
    private readonly ILogger<IpcRequestHandler> _log;
    private readonly IAgentStateProvider _state;
    private readonly AuditEngine _audit;
    private readonly PolicyStore _policy;
    private readonly DeviceStateStore _deviceStore;
    private readonly IHardwareIdProvider _hwid;
    private readonly UninstallAttemptGuard _guard;
    private readonly UninstallCoordinator _uninstall;
    private readonly HeartbeatSignal _heartbeat;
    private readonly ServerOptions _serverOptions;

    private static readonly string Version =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public IpcRequestHandler(
        ILogger<IpcRequestHandler> log,
        IAgentStateProvider state,
        AuditEngine audit,
        PolicyStore policy,
        DeviceStateStore deviceStore,
        IHardwareIdProvider hwid,
        UninstallAttemptGuard guard,
        UninstallCoordinator uninstall,
        HeartbeatSignal heartbeat,
        IOptions<ServerOptions> serverOptions)
    {
        _log = log;
        _state = state;
        _audit = audit;
        _policy = policy;
        _deviceStore = deviceStore;
        _hwid = hwid;
        _guard = guard;
        _uninstall = uninstall;
        _heartbeat = heartbeat;
        _serverOptions = serverOptions.Value;
    }

    public async Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken ct)
    {
        try
        {
            return request.Op switch
            {
                IpcOps.Ping => IpcResponse.Success(request.Id, new PingPayload
                {
                    Version = Version,
                    UptimeSec = _state.Current.UptimeSeconds
                }),

                IpcOps.GetStatus => IpcResponse.Success(request.Id, _state.Current),

                IpcOps.GetPolicy => IpcResponse.Success(request.Id, _policy.Current),

                IpcOps.RunAuditNow => IpcResponse.Success(request.Id,
                    await _audit.RunAsync(_state.Current.LockoutActive, ct)),

                IpcOps.RefreshNow => RequestRefresh(request),

                IpcOps.LockoutState => IpcResponse.Success(request.Id, BuildLockoutState()),

                IpcOps.UninstallChallenge => HandleChallenge(request),

                IpcOps.UninstallVerify => await HandleVerifyAsync(request, ct),

                _ => IpcResponse.Failure(request.Id, $"פעולה לא נתמכת: {request.Op}")
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "טיפול בבקשת IPC {Op} נכשל.", request.Op);
            return IpcResponse.Failure(request.Id, "שגיאה פנימית בשירות.");
        }
    }

    private IpcResponse RequestRefresh(IpcRequest request)
    {
        _heartbeat.RequestNow();
        _log.LogInformation("בקשת רענון מהמגש. הפעימה הבאה תצא מיד.");

        return IpcResponse.Success(request.Id);
    }

    private LockoutStateResult BuildLockoutState()
    {
        var snapshot = _state.Current;
        var (guardLocked, guardUntil) = _guard.GetLockoutState();

        // שתי נעילות שונות: נעילת רשת מהמדיניות, ונעילת ניסיונות הסרה
        if (guardLocked)
            return new LockoutStateResult
            {
                Active = true,
                Until = guardUntil,
                Reason = "חסימה זמנית לאחר ניסיונות הסרה שגויים"
            };

        return new LockoutStateResult
        {
            Active = snapshot.LockoutActive,
            Until = snapshot.LockoutUntil,
            Reason = snapshot.LockoutReason
        };
    }

    private IpcResponse HandleChallenge(IpcRequest request)
    {
        var payload = request.Read<UninstallChallengePayload>();
        var device = _deviceStore.Load();
        var hwid = _hwid.GetHardwareId();

        var (challenge, rejection) = _guard.IssueChallenge(hwid, device.UninstallKeyMode);

        if (challenge is null)
            return IpcResponse.Failure(request.Id, rejection?.Message ?? "לא ניתן להפיק אתגר כעת.");

        _log.LogInformation("הופק אתגר הסרה. סיבה שנמסרה: {Reason}", payload?.Reason ?? "לא צוינה");

        return IpcResponse.Success(request.Id, new UninstallChallengeResult
        {
            Challenge = challenge.ToDisplayString(),
            ExpiresUtc = challenge.IssuedUtc.Add(_guard.ChallengeValidity),
            Mode = device.UninstallKeyMode.ToString()
        });
    }

    private async Task<IpcResponse> HandleVerifyAsync(IpcRequest request, CancellationToken ct)
    {
        var payload = request.Read<UninstallVerifyPayload>();

        if (payload is null || string.IsNullOrWhiteSpace(payload.Response))
            return IpcResponse.Failure(request.Id, "לא הוזן קוד הסרה.");

        var device = _deviceStore.Load();
        var hwid = _hwid.GetHardwareId();

        /*
         * המפתח מהרישום, ובהיעדרו זה שהוטבע בהתקנה.
         *
         * בהתקנה ללא חשבון אין רישום ולכן אין מפתח מהשרת, והמוטבע
         * הוא היחיד שקיים. הסדר הזה ולא ההפוך: מחשב רשום מקבל את
         * המפתח העדכני מהשרת, ולא נשאר תקוע על עותק ישן מיום
         * ההתקנה.
         */
        var uninstallKey = device.UninstallPublicKeyPem
            ?? _serverOptions.UninstallPublicKeyPem;

        var result = _guard.Verify(
            payload.Challenge,
            payload.Response,
            hwid,
            device.UninstallKeyMode,
            uninstallKey,
            device.ServerPublicKeyPem,
            device.GetDeviceSecret());

        if (!result.Granted)
        {
            _log.LogWarning("אימות קוד הסרה נכשל: {Status}", result.Status);

            return IpcResponse.Success(request.Id, new UninstallVerifyResult
            {
                Granted = false,
                AttemptsLeft = result.AttemptsLeft,
                LockoutUntil = result.LockoutUntil,
                Message = result.Message
            });
        }

        var token = _guard.GetGrantedToken();

        // האימות הצליח: מפרקים את האכיפה ומדווחים לשרת
        await _uninstall.DisarmAsync(token, ct);

        _log.LogWarning("ההסרה אושרה בקוד תקף. האכיפה פורקה.");

        return IpcResponse.Success(request.Id, new UninstallVerifyResult
        {
            Granted = true,
            Token = token,
            Message = "הקוד אומת. האכיפה הוסרה וניתן להמשיך בהסרת התוכנה."
        });
    }
}
