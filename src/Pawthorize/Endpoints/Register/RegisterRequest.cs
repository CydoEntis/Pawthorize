namespace Pawthorize.Endpoints.Register;

/// <summary>
/// Request model for user registration.
/// </summary>
public class RegisterRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// User's first name (given name).
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// User's last name (family name).
    /// </summary>
    public string LastName { get; set; } = string.Empty;
}
