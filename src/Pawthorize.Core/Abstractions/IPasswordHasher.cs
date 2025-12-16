namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Abstraction for password hashing and verification.
/// </summary>
public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash);
}