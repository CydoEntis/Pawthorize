namespace Pawthorize.Endpoints.ChangeEmail;

/// <summary>
/// Request model for changing email address (for authenticated users).
/// </summary>
public class ChangeEmailRequest
{
    /// <summary>
    /// The new email address to change to.
    /// </summary>
    public string NewEmail { get; set; } = string.Empty;

    /// <summary>
    /// Current password for confirmation (required if RequirePasswordConfirmation is true).
    /// </summary>
    public string Password { get; set; } = string.Empty;
}
