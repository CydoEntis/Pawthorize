using System.Security.Cryptography;
using System.Text;

namespace Pawthorize.Internal;

/// <summary>
/// Utility for hashing tokens to store securely in the database.
/// Prevents token leakage if database is compromised.
/// This class is internal and not part of the public API.
/// </summary>
internal static class TokenHasher
{
    /// <summary>
    /// Hash a token using SHA256.
    /// This is a one-way hash - the original token cannot be recovered.
    /// </summary>
    /// <param name="token">The raw token to hash</param>
    /// <returns>Base64-encoded hash of the token</returns>
    public static string HashToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token cannot be null or empty", nameof(token));

        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var hashBytes = SHA256.HashData(tokenBytes);

        return Convert.ToBase64String(hashBytes);
    }

    /// <summary>
    /// Verify if a raw token matches a stored hash.
    /// </summary>
    /// <param name="rawToken">The raw token to verify</param>
    /// <param name="storedHash">The hash stored in the database</param>
    /// <returns>True if the token matches the hash, false otherwise</returns>
    public static bool VerifyToken(string rawToken, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(rawToken) || string.IsNullOrWhiteSpace(storedHash))
            return false;

        var computedHash = HashToken(rawToken);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computedHash),
            Encoding.UTF8.GetBytes(storedHash)
        );
    }
}
