using Pawthorize.Models;

namespace Pawthorize.Abstractions;

/// <summary>
/// Service for generating and validating OAuth state tokens (CSRF protection).
/// </summary>
public interface IStateTokenService
{
    /// <summary>
    /// Generates a new state token with optional return URL.
    /// </summary>
    /// <param name="returnUrl">Optional URL to redirect to after OAuth.</param>
    /// <param name="codeVerifier">Optional PKCE code verifier.</param>
    /// <param name="action">The action type: "login" (default) or "link".</param>
    /// <param name="userId">The user ID for link actions.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The generated state token string.</returns>
    Task<string> GenerateStateTokenAsync(
        string? returnUrl = null,
        string? codeVerifier = null,
        string action = "login",
        string? userId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a state token and retrieves associated data.
    /// </summary>
    /// <param name="state">The state token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validated state token data.</returns>
    /// <exception cref="Errors.OAuthStateValidationError">Thrown if state is invalid or expired.</exception>
    Task<StateTokenData> ValidateAndConsumeStateTokenAsync(
        string state,
        CancellationToken cancellationToken = default);
}
