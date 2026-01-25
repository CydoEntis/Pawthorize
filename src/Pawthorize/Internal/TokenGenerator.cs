using System.Security.Cryptography;

namespace Pawthorize.Internal;

/// <summary>
/// Utility for generating cryptographically secure tokens.
/// This class is internal and not part of the public API.
/// </summary>
internal static class TokenGenerator
{
    /// <summary>
    /// Generate a cryptographically secure random token.
    /// </summary>
    /// <param name="length">Token length in bytes (default: 32)</param>
    /// <returns>URL-safe base64 encoded token</returns>
    public static string GenerateToken(int length = 32)
    {
        if (length < 16)
            throw new ArgumentException("Token length must be at least 16 bytes", nameof(length));

        var randomBytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        // Convert to URL-safe base64 (replace + with - and / with _)
        return Convert.ToBase64String(randomBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
