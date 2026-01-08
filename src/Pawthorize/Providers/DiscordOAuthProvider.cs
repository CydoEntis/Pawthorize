using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Models;

namespace Pawthorize.Providers;

/// <summary>
/// Discord OAuth 2.0 provider implementation.
/// </summary>
public class DiscordOAuthProvider : OAuthProviderBase
{
    private readonly ILogger<DiscordOAuthProvider> _logger;
    private readonly OAuthOptions _oauthOptions;

    public DiscordOAuthProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<DiscordOAuthProvider> logger)
        : base(httpClientFactory, oauthOptions, logger)
    {
        _logger = logger;
        _oauthOptions = oauthOptions.Value;
    }

    public override string ProviderName => "discord";

    protected override string AuthorizationEndpoint => "https://discord.com/api/oauth2/authorize";
    protected override string TokenEndpoint => "https://discord.com/api/oauth2/token";
    protected override string UserInfoEndpoint => "https://discord.com/api/users/@me";
    protected override string[] DefaultScopes => new[] { "identify", "email" };

    public override async Task<ExternalUserInfo> GetUserInfoAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Fetching Discord user info");

        var userData = await FetchUserInfoJsonAsync(accessToken, cancellationToken: cancellationToken);

        var providerId = userData["id"].GetString()
            ?? throw new OAuthProviderError(ProviderName, "invalid_response", "User ID is missing");

        var username = userData.TryGetValue("username", out var usernameElement) ? usernameElement.GetString() : null;
        var discriminator = userData.TryGetValue("discriminator", out var discriminatorElement)
            ? discriminatorElement.GetString()
            : null;

        var email = userData.TryGetValue("email", out var emailElement) ? emailElement.GetString() : null;
        var emailVerified = userData.TryGetValue("verified", out var verifiedElement)
            && verifiedElement.GetBoolean();

        var config = GetProviderConfig();
        if (config.RequireVerifiedEmail && (!emailVerified || string.IsNullOrEmpty(email)))
        {
            throw new OAuthProviderError(ProviderName, "email_not_verified",
                "Email verification is required but email is not verified by Discord");
        }

        var avatar = userData.TryGetValue("avatar", out var avatarElement) ? avatarElement.GetString() : null;
        string? profilePictureUrl = null;
        if (!string.IsNullOrEmpty(avatar))
        {
            profilePictureUrl = $"https://cdn.discordapp.com/avatars/{providerId}/{avatar}.png";
        }

        var globalName = userData.TryGetValue("global_name", out var globalNameElement)
            ? globalNameElement.GetString()
            : null;

        var displayUsername = discriminator != null && discriminator != "0"
            ? $"{username}#{discriminator}"
            : username;

        _logger.LogInformation("Successfully retrieved Discord user info for user {ProviderId}", providerId);

        return new ExternalUserInfo
        {
            ProviderId = providerId,
            Email = email,
            EmailVerified = emailVerified,
            Name = globalName ?? displayUsername,
            Username = displayUsername,
            ProfilePictureUrl = profilePictureUrl
        };
    }
}
