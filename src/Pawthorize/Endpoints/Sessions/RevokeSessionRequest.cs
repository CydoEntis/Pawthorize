namespace Pawthorize.Endpoints.Sessions;

/// <summary>
/// Request model for revoking a specific session by its ID.
/// </summary>
public class RevokeSessionRequest
{
    /// <summary>
    /// The unique session ID (token hash) to revoke.
    /// </summary>
    public string SessionId { get; set; } = string.Empty;
}
