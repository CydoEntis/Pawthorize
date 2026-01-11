namespace Pawthorize.Configuration;

/// <summary>
/// Configuration options for password policy enforcement.
/// Enforces strong passwords to protect against weak password attacks.
/// </summary>
public class PasswordPolicyOptions
{
    /// <summary>
    /// Minimum password length.
    /// Default: 8 characters
    /// </summary>
    public int MinLength { get; set; } = 8;

    /// <summary>
    /// Maximum password length.
    /// Default: 128 characters
    /// </summary>
    public int MaxLength { get; set; } = 128;

    /// <summary>
    /// Require at least one uppercase letter (A-Z).
    /// Default: true
    /// </summary>
    public bool RequireUppercase { get; set; } = true;

    /// <summary>
    /// Require at least one lowercase letter (a-z).
    /// Default: true
    /// </summary>
    public bool RequireLowercase { get; set; } = true;

    /// <summary>
    /// Require at least one digit (0-9).
    /// Default: true
    /// </summary>
    public bool RequireDigit { get; set; } = true;

    /// <summary>
    /// Require at least one special character.
    /// Default: true
    /// </summary>
    public bool RequireSpecialChar { get; set; } = true;

    /// <summary>
    /// Block commonly used passwords (e.g., "password", "123456").
    /// Uses a list of the top 1000 most common passwords.
    /// Default: true
    /// </summary>
    public bool BlockCommonPasswords { get; set; } = true;

    /// <summary>
    /// Special characters that are considered valid for the RequireSpecialChar check.
    /// Default value contains common special characters.
    /// </summary>
    public string SpecialCharacters { get; set; } = "!@#$%^&*()_+-=[]{}|;:,.<>?";
}
