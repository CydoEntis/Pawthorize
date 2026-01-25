namespace Pawthorize.Endpoints.Sessions;

/// <summary>
/// Request model for revoking all other sessions.
/// </summary>
public class RevokeAllOtherSessionsRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}
