using System.Security.Cryptography;
using System.Text;

namespace Pawthorize.Utilities;

/// <summary>
/// Helper methods for PKCE (Proof Key for Code Exchange) implementation.
/// </summary>
public static class PkceHelper
{
    /// <summary>
    /// Generates a cryptographically secure code verifier for PKCE.
    /// </summary>
    /// <param name="length">Length of the verifier (43-128 characters).</param>
    /// <returns>Base64url-encoded code verifier.</returns>
    public static string GenerateCodeVerifier(int length = 64)
    {
        if (length < 43 || length > 128)
            throw new ArgumentException("Code verifier length must be between 43 and 128 characters", nameof(length));

        var randomBytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        return Convert.ToBase64String(randomBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")
            .Substring(0, length);
    }

    /// <summary>
    /// Generates a code challenge from a code verifier using SHA256.
    /// </summary>
    /// <param name="codeVerifier">The code verifier.</param>
    /// <returns>Base64url-encoded SHA256 hash of the verifier.</returns>
    public static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));

        return Convert.ToBase64String(challengeBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
