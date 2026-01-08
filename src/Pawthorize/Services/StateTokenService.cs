using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Models;

namespace Pawthorize.Services;

/// <summary>
/// Service for generating and validating OAuth state tokens (CSRF protection).
/// </summary>
public class StateTokenService<TStateToken> : IStateTokenService
    where TStateToken : class, IStateToken, new()
{
    private readonly IStateTokenRepository<TStateToken> _stateTokenRepository;
    private readonly OAuthOptions _oauthOptions;
    private readonly ILogger<StateTokenService<TStateToken>> _logger;

    public StateTokenService(
        IStateTokenRepository<TStateToken> stateTokenRepository,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<StateTokenService<TStateToken>> logger)
    {
        _stateTokenRepository = stateTokenRepository;
        _oauthOptions = oauthOptions.Value;
        _logger = logger;
    }

    public async Task<string> GenerateStateTokenAsync(
        string? returnUrl = null,
        string? codeVerifier = null,
        CancellationToken cancellationToken = default)
    {
        var token = GenerateCryptographicToken(32);
        var createdAt = DateTime.UtcNow;
        var expiresAt = createdAt.AddMinutes(_oauthOptions.StateTokenExpirationMinutes);

        _logger.LogDebug("Generating OAuth state token, expires at {ExpiresAt}", expiresAt);

        // Create state token using object initializer with casting to access setters
        var stateToken = (TStateToken)Activator.CreateInstance(typeof(TStateToken))!;
        var stateTokenType = typeof(TStateToken);

        stateTokenType.GetProperty(nameof(IStateToken.Token))?.SetValue(stateToken, token);
        stateTokenType.GetProperty(nameof(IStateToken.ReturnUrl))?.SetValue(stateToken, returnUrl);
        stateTokenType.GetProperty(nameof(IStateToken.CodeVerifier))?.SetValue(stateToken, codeVerifier);
        stateTokenType.GetProperty(nameof(IStateToken.CreatedAt))?.SetValue(stateToken, createdAt);
        stateTokenType.GetProperty(nameof(IStateToken.ExpiresAt))?.SetValue(stateToken, expiresAt);

        await _stateTokenRepository.CreateAsync(stateToken, cancellationToken);

        _logger.LogInformation("Generated and stored OAuth state token");

        return token;
    }

    public async Task<StateTokenData> ValidateAndConsumeStateTokenAsync(
        string state,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Validating OAuth state token");

        if (string.IsNullOrWhiteSpace(state))
        {
            _logger.LogWarning("State token validation failed: State is null or empty");
            throw new OAuthStateValidationError("State token is required");
        }

        var stateToken = await _stateTokenRepository.FindByTokenAsync(state, cancellationToken);

        if (stateToken == null)
        {
            _logger.LogWarning("State token validation failed: Token not found");
            throw new OAuthStateValidationError("Invalid or expired state token");
        }

        if (stateToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("State token validation failed: Token expired at {ExpiresAt}", stateToken.ExpiresAt);
            await _stateTokenRepository.DeleteAsync(state, cancellationToken);
            throw new OAuthStateValidationError("State token has expired. Please try signing in again.");
        }

        if (!ConstantTimeEquals(stateToken.Token, state))
        {
            _logger.LogWarning("State token validation failed: Token mismatch (possible CSRF attack)");
            throw new OAuthStateValidationError("State token validation failed");
        }

        await _stateTokenRepository.DeleteAsync(state, cancellationToken);

        _logger.LogInformation("Successfully validated and consumed OAuth state token");

        return new StateTokenData
        {
            Token = stateToken.Token,
            ReturnUrl = stateToken.ReturnUrl,
            CodeVerifier = stateToken.CodeVerifier,
            ExpiresAt = stateToken.ExpiresAt
        };
    }

    private static string GenerateCryptographicToken(int byteLength = 32)
    {
        var randomBytes = new byte[byteLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }

    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
            return false;

        var result = 0;
        for (var i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }
}
