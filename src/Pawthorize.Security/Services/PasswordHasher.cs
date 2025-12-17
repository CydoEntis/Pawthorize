using Pawthorize.Core.Abstractions;
using BCrypt.Net;

namespace Pawthorize.Security.Services;

/// <summary>
/// BCrypt-based password hasher.
/// Uses adaptive hashing with configurable work factor.
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    private readonly int _workFactor;

    /// <summary>
    /// Create a password hasher with specified work factor.
    /// </summary>
    /// <param name="workFactor">BCrypt work factor (10-14 recommended, default: 12)</param>
    public PasswordHasher(int workFactor = 12)
    {
        if (workFactor < 10 || workFactor > 14)
        {
            throw new ArgumentOutOfRangeException(
                nameof(workFactor),
                "Work factor must be between 10 and 14 for production use.");
        }

        _workFactor = workFactor;
    }

    /// <summary>
    /// Hash a plaintext password using BCrypt.
    /// </summary>
    /// <param name="password">Plaintext password to hash</param>
    /// <returns>BCrypt hash (includes salt and work factor)</returns>
    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentNullException(nameof(password), "Password cannot be null or empty.");
        }

        return BCrypt.Net.BCrypt.HashPassword(password, _workFactor);
    }

    /// <summary>
    /// Verify a password against a BCrypt hash.
    /// </summary>
    /// <param name="password">Plaintext password to verify</param>
    /// <param name="hash">BCrypt hash to verify against</param>
    /// <returns>True if password matches hash, false otherwise</returns>
    public bool VerifyPassword(string password, string hash)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentNullException(nameof(password), "Password cannot be null or empty.");
        }

        if (string.IsNullOrEmpty(hash))
        {
            throw new ArgumentNullException(nameof(hash), "Hash cannot be null or empty.");
        }

        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch (SaltParseException)
        {
            return false;
        }
    }
}