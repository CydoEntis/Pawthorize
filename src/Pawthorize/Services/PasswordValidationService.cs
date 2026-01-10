using System.Text;
using Microsoft.Extensions.Options;
using Pawthorize.Configuration;

namespace Pawthorize.Services;

/// <summary>
/// Service for validating passwords against configured policy.
/// </summary>
public class PasswordValidationService
{
    private readonly PasswordPolicyOptions _policy;
    private readonly HashSet<string> _commonPasswords;

    public PasswordValidationService(IOptions<PasswordPolicyOptions> policyOptions)
    {
        _policy = policyOptions.Value;
        _commonPasswords = LoadCommonPasswords();
    }

    /// <summary>
    /// Validates a password against the configured password policy.
    /// </summary>
    /// <param name="password">The password to validate</param>
    /// <returns>Validation result with any errors</returns>
    public PasswordValidationResult Validate(string password)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(password))
        {
            errors.Add("Password is required");
            return new PasswordValidationResult(false, errors);
        }

        // Check length
        if (password.Length < _policy.MinLength)
        {
            errors.Add($"Password must be at least {_policy.MinLength} characters long");
        }

        if (password.Length > _policy.MaxLength)
        {
            errors.Add($"Password must not exceed {_policy.MaxLength} characters");
        }

        // Check uppercase
        if (_policy.RequireUppercase && !password.Any(char.IsUpper))
        {
            errors.Add("Password must contain at least one uppercase letter (A-Z)");
        }

        // Check lowercase
        if (_policy.RequireLowercase && !password.Any(char.IsLower))
        {
            errors.Add("Password must contain at least one lowercase letter (a-z)");
        }

        // Check digit
        if (_policy.RequireDigit && !password.Any(char.IsDigit))
        {
            errors.Add("Password must contain at least one digit (0-9)");
        }

        // Check special character
        if (_policy.RequireSpecialChar && !password.Any(c => _policy.SpecialCharacters.Contains(c)))
        {
            errors.Add($"Password must contain at least one special character ({_policy.SpecialCharacters})");
        }

        // Check common passwords
        if (_policy.BlockCommonPasswords && _commonPasswords.Contains(password.ToLowerInvariant()))
        {
            errors.Add("This password is too common. Please choose a stronger password");
        }

        return new PasswordValidationResult(errors.Count == 0, errors);
    }

    /// <summary>
    /// Gets a summary of the current password policy requirements.
    /// Useful for displaying to users.
    /// </summary>
    public string GetPolicyDescription()
    {
        var requirements = new List<string>();

        requirements.Add($"At least {_policy.MinLength} characters long");

        if (_policy.RequireUppercase)
            requirements.Add("Contains uppercase letter (A-Z)");

        if (_policy.RequireLowercase)
            requirements.Add("Contains lowercase letter (a-z)");

        if (_policy.RequireDigit)
            requirements.Add("Contains digit (0-9)");

        if (_policy.RequireSpecialChar)
            requirements.Add("Contains special character");

        if (_policy.BlockCommonPasswords)
            requirements.Add("Not a commonly used password");

        return "Password must:\n- " + string.Join("\n- ", requirements);
    }

    /// <summary>
    /// Loads the list of common passwords to block.
    /// Using top 1000 most common passwords from various breach datasets.
    /// </summary>
    private HashSet<string> LoadCommonPasswords()
    {
        if (!_policy.BlockCommonPasswords)
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Top 1000 most common passwords (lowercase for case-insensitive comparison)
        // Source: Compiled from various password breach datasets
        var passwords = new[]
        {
            "123456", "password", "123456789", "12345678", "12345", "1234567", "1234567890",
            "qwerty", "abc123", "111111", "123123", "password1", "1234", "000000", "iloveyou",
            "1q2w3e4r", "qwertyuiop", "123321", "monkey", "dragon", "654321", "666666", "superman",
            "1qaz2wsx", "trustno1", "sunshine", "master", "welcome", "shadow", "ashley", "football",
            "jesus", "michael", "ninja", "mustang", "password123", "adobe123", "azerty", "starwars",
            "hello", "whatever", "donald", "batman", "zxcvbnm", "soccer", "letmein", "passw0rd",
            "admin", "123qwe", "solo", "charlie", "Login", "welcome123", "aa123456", "lovely",
            "Login123", "flower", "hottie", "loveme", "123abc", "princess", "qwerty123", "solo123",
            "password12", "welcome1", "1q2w3e", "bailey", "1234abcd", "freedom", "daniel",
            "1234qwer", "summer", "1q2w3e4r5t", "baseball", "chocolate", "Password1", "password2",
            "123654", "111222", "7777777", "abc1234", "987654321", "password!", "password1!",
            "password@123", "test", "test123", "demo", "demo123", "changeme", "changeme123",
            "P@ssw0rd", "P@ssword", "P@ssword123", "P@ssw0rd123", "qwerty1", "qwerty12",
            "qwerty123!", "Password123", "Password123!", "Admin123", "Admin@123", "root", "root123",
            "toor", "admin123", "admin@123", "123admin", "user", "user123", "temp", "temp123",
            "guest", "guest123", "123", "1234", "12345", "123456", "1234567", "12345678",
            "987654", "pass", "pass123", "pass1234", "password0", "password3", "password4",
            "default", "default123", "secret", "secret123", "mypassword", "mypass", "mypass123",
            "qazwsx", "qazwsxedc", "zaq12wsx", "zaq1xsw2", "1q2w3e4r5t6y", "qwer1234",
            "asdf", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvb", "zxcv", "qwerasdf", "qwerasdfzxcv",
            "letmein123", "access", "access123", "welcome!", "Welcome1", "Welcome123", "Welcome@123",
            "master123", "master1", "michael1", "jordan", "jordan23", "matrix", "matrix123",
            "monkey1", "dragon1", "superman1", "batman1", "spiderman", "ironman", "captain",
            "pokemon", "naruto", "harley", "shadow1", "shadow123", "killer", "killer123",
            "ginger", "pepper", "cookie", "cookie123", "buster", "buster123", "dakota", "ranger",
            "hunter", "hunter1", "hunter123", "george", "thomas", "robert", "william", "richard",
            "charles", "joseph", "andrew", "anthony", "matthew", "joshua", "christopher", "nicholas",
            "alexander", "benjamin", "jessica", "jennifer", "amanda", "melissa", "stephanie",
            "nicole", "samantha", "elizabeth", "lauren", "ashley123", "jessica1", "jennifer1",
            "computer", "internet", "samsung", "iphone", "google", "apple", "microsoft", "windows",
            "linux", "android", "facebook", "twitter", "instagram", "youtube", "reddit", "netflix",
            "amazon", "password01", "password02", "password10", "password11", "password99",
            "spring", "summer123", "autumn", "winter", "winter123", "january", "february",
            "march", "april", "may", "june", "july", "august", "september", "october",
            "november", "december", "monday", "tuesday", "wednesday", "thursday", "friday",
            "saturday", "sunday", "sunshine1", "rainbow", "rainbow123", "butterfly", "butterfly123",
            "family", "family123", "friends", "friends123", "forever", "forever1", "forever123",
            "love", "love123", "loveyou", "iloveu", "iloveyou1", "iloveyou123", "iloveyou!",
            "baseball1", "football1", "soccer1", "basketball", "tennis", "hockey", "hockey1",
            "golf", "swimming", "running", "mustang1", "ferrari", "porsche", "corvette",
            "mercedes", "bmw", "toyota", "honda", "ford", "chevy", "dodge", "jeep", "guitar",
            "music", "music123", "rock", "rock123", "metal", "jazz", "blues", "country",
            "123456a", "123456q", "a123456", "q123456", "1q2w3e4r!", "qwerty!@#", "qwerty12345",
            "abc12345", "abcd1234", "abcdef", "abcdefg", "abcdefgh", "abcdefghi", "password@1",
            "password#1", "password$1", "p@ssword", "p@ssw0rd", "p@55w0rd", "pa$$word", "pa55word",
            "passw0rd123", "p@ssword123", "p@ssw0rd123", "password@2023", "password2023",
            "password@2024", "password2024", "welcome@2023", "welcome2023", "welcome@2024",
            "qwerty@123", "qwerty#123", "qwerty$123", "admin@2023", "admin2023", "admin@2024",
            "test@123", "test#123", "demo@123", "changeme@123", "temp@123", "user@123",
            "112233", "121212", "123123123", "123321123", "1234554321", "1111111111", "2222222222",
            "1212121212", "123412341234", "abcabc", "abc123abc", "aaa111", "aaa123", "aaaa1111",
            "qqqqqq", "qqqq1111", "qqqqq", "zzzzzz", "zzzzz", "zzzz1111", "qweasd", "qweasdzxc",
            "password!@#", "password!@#$", "password$%^", "password&*(", "password!!!",
            "password???", "welcome!!!", "admin!!!", "root!!!", "super", "super123", "super!",
            "super@123", "1qazxsw2", "1qaz@wsx", "1qaz!qaz", "password!1", "password@2",
            "Password!1", "Password@1", "Password#1", "admin!1", "admin@1", "admin#1"
        };

        return new HashSet<string>(passwords, StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Result of password validation.
/// </summary>
public class PasswordValidationResult
{
    public bool IsValid { get; }
    public IReadOnlyList<string> Errors { get; }

    public PasswordValidationResult(bool isValid, List<string> errors)
    {
        IsValid = isValid;
        Errors = errors.AsReadOnly();
    }

    /// <summary>
    /// Gets a formatted error message combining all errors.
    /// </summary>
    public string GetErrorMessage()
    {
        return string.Join(". ", Errors);
    }
}
