using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Services.OAuth.Models;

namespace Pawthorize.Services.OAuth.Providers;

/// <summary>
/// Google OAuth 2.0 provider implementation.
/// </summary>
public class GoogleOAuthProvider : OAuthProviderBase
{
    private readonly ILogger<GoogleOAuthProvider> _logger;
    private readonly OAuthOptions _oauthOptions;

    public GoogleOAuthProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<GoogleOAuthProvider> logger)
        : base(httpClientFactory, oauthOptions, logger)
    {
        _logger = logger;
        _oauthOptions = oauthOptions.Value;
    }

    public override string ProviderName => "google";

    protected override string AuthorizationEndpoint => "https://accounts.google.com/o/oauth2/v2/auth";
    protected override string TokenEndpoint => "https://oauth2.googleapis.com/token";
    protected override string UserInfoEndpoint => "https://www.googleapis.com/oauth2/v2/userinfo";
    protected override string[] DefaultScopes => new[] { "openid", "profile", "email" };

    public override async Task<ExternalUserInfo> GetUserInfoAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Fetching Google user info");

        var userData = await FetchUserInfoJsonAsync(accessToken, cancellationToken: cancellationToken);

        var providerId = userData["id"].GetString()
            ?? throw new OAuthProviderError(ProviderName, "invalid_response", "User ID is missing");

        var email = userData.TryGetValue("email", out var emailElement) ? emailElement.GetString() : null;
        var emailVerified = userData.TryGetValue("verified_email", out var verifiedElement)
            && verifiedElement.GetBoolean();

        var config = GetProviderConfig();
        if (config.RequireVerifiedEmail && (!emailVerified || string.IsNullOrEmpty(email)))
        {
            throw new OAuthProviderError(ProviderName, "email_not_verified",
                "Email verification is required but email is not verified by Google");
        }

        var name = userData.TryGetValue("name", out var nameElement) ? nameElement.GetString() : null;
        var givenName = userData.TryGetValue("given_name", out var givenElement) ? givenElement.GetString() : null;
        var familyName = userData.TryGetValue("family_name", out var familyElement) ? familyElement.GetString() : null;
        var picture = userData.TryGetValue("picture", out var pictureElement) ? pictureElement.GetString() : null;

        _logger.LogInformation("Successfully retrieved Google user info for user {ProviderId}", providerId);

        return new ExternalUserInfo
        {
            ProviderId = providerId,
            Email = email,
            EmailVerified = emailVerified,
            Name = name,
            GivenName = givenName,
            FamilyName = familyName,
            Username = null,
            ProfilePictureUrl = picture
        };
    }
}
