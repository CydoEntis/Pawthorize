using FluentAssertions;
using Pawthorize.Security.Services;
using Xunit;

namespace Pawthorize.Security.Tests;

/// <summary>
/// Unit tests for PasswordHasher service.
/// Tests BCrypt password hashing and verification.
/// </summary>
public class PasswordHasherTests
{
    private readonly PasswordHasher _hasher;

    public PasswordHasherTests()
    {
        _hasher = new PasswordHasher();
    }

    [Fact]
    public void HashPassword_WithValidPassword_ShouldReturnBCryptHash()
    {
        var password = "MySecurePassword123!";

        var hash = _hasher.HashPassword(password);

        hash.Should().NotBeNullOrEmpty();
        hash.Should().NotBe(password); // Hash should be different from plaintext
        hash.Should().StartWith("$2"); // BCrypt hashes start with $2
        hash.Length.Should().Be(60); // BCrypt hashes are 60 characters
    }

    [Fact]
    public void HashPassword_SamePassword_ShouldGenerateDifferentHashes()
    {
        var password = "MySecurePassword123!";

        var hash1 = _hasher.HashPassword(password);
        var hash2 = _hasher.HashPassword(password);

        hash1.Should().NotBe(hash2); // BCrypt uses random salt, so hashes differ
    }

    [Fact]
    public void VerifyPassword_WithCorrectPassword_ShouldReturnTrue()
    {
        var password = "MySecurePassword123!";
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword(password, hash);

        result.Should().BeTrue();
    }

    [Fact]
    public void VerifyPassword_WithIncorrectPassword_ShouldReturnFalse()
    {
        var correctPassword = "MySecurePassword123!";
        var incorrectPassword = "WrongPassword456!";
        var hash = _hasher.HashPassword(correctPassword);

        var result = _hasher.VerifyPassword(incorrectPassword, hash);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifyPassword_WithEmptyPassword_ShouldReturnFalse()
    {
        var password = "MySecurePassword123!";
        var hash = _hasher.HashPassword(password);

        var result = _hasher.VerifyPassword(string.Empty, hash);

        result.Should().BeFalse();
    }

    [Theory]
    [InlineData("short")]
    [InlineData("averagelengthpassword")]
    [InlineData("verylongpasswordwithlotsofcharacters1234567890!@#$%^&*()")]
    public void HashPassword_WithVariousLengths_ShouldWorkCorrectly(string password)
    {
        var hash = _hasher.HashPassword(password);
        var isValid = _hasher.VerifyPassword(password, hash);

        hash.Should().NotBeNullOrEmpty();
        hash.Should().StartWith("$2");
        isValid.Should().BeTrue();
    }

    [Theory]
    [InlineData("Password123!")]
    [InlineData("пароль123")] // Cyrillic
    [InlineData("密码123")] // Chinese
    [InlineData("🔐secure🔑")] // Emojis
    public void HashPassword_WithSpecialCharacters_ShouldWorkCorrectly(string password)
    {
        var hash = _hasher.HashPassword(password);
        var isValid = _hasher.VerifyPassword(password, hash);

        isValid.Should().BeTrue();
    }

    [Fact]
    public void VerifyPassword_WithNullHash_ShouldReturnFalse()
    {
        var password = "MySecurePassword123!";

        var result = _hasher.VerifyPassword(password, null!);

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifyPassword_WithInvalidHash_ShouldReturnFalse()
    {
        var password = "MySecurePassword123!";
        var invalidHash = "not-a-valid-bcrypt-hash";

        var result = _hasher.VerifyPassword(password, invalidHash);

        result.Should().BeFalse();
    }
}
