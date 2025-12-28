namespace Pawthorize.Core.Models;

/// <summary>
/// Password hashing configuration
/// </summary>
public class PasswordHashingOptions
{
    /// <summary>
    /// BCrypt work factor (higher = more secure but slower)
    /// Default: 12 (recommended)
    /// Range: 10-14 for production
    /// </summary>
    /// <remarks>
    /// Work factor of 12 = ~250ms to hash on modern CPU
    /// Each +1 doubles the time (exponential)
    /// </remarks>
    public int WorkFactor { get; set; } = 12;
}