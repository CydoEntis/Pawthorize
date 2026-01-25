namespace Pawthorize.Services;

/// <summary>
/// Defines the contract for OAuth 2.0 providers.
/// </summary>
public interface IExternalAuthProvider
{
    /// <summary>
    /// Gets the provider name (e.g., "google", "discord", "github").
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Generates the OAuth authorization URL to redirect users to.
    /// </summary>
    /// <param name="state">CSRF protection state token.</param>
    /// <param name="redirectUri">The callback URL after authorization.</param>
    /// <param name="codeChallenge">Optional PKCE code challenge.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authorization URL.</returns>
    Task<string> GetAuthorizationUrlAsync(
        string state,
        string redirectUri,
        string? codeChallenge = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges the authorization code for an access token.
    /// </summary>
    /// <param name="code">The authorization code from the callback.</param>
    /// <param name="redirectUri">The same redirect URI used in authorization.</param>
    /// <param name="codeVerifier">Optional PKCE code verifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The OAuth token response.</returns>
    Task<OAuth.Models.OAuthToken> ExchangeCodeForTokenAsync(
        string code,
        string redirectUri,
        string? codeVerifier = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Fetches user information from the provider using the access token.
    /// </summary>
    /// <param name="accessToken">The OAuth access token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>External user information.</returns>
    Task<OAuth.Models.ExternalUserInfo> GetUserInfoAsync(
        string accessToken,
        CancellationToken cancellationToken = default);
}
