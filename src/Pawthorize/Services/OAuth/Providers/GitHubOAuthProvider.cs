using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Services.OAuth.Models;

namespace Pawthorize.Services.OAuth.Providers;

/// <summary>
/// GitHub OAuth 2.0 provider implementation.
/// </summary>
public class GitHubOAuthProvider : OAuthProviderBase
{
    private readonly ILogger<GitHubOAuthProvider> _logger;
    private readonly OAuthOptions _oauthOptions;
    private readonly IHttpClientFactory _httpClientFactory;

    public GitHubOAuthProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<GitHubOAuthProvider> logger)
        : base(httpClientFactory, oauthOptions, logger)
    {
        _logger = logger;
        _oauthOptions = oauthOptions.Value;
        _httpClientFactory = httpClientFactory;
    }

    public override string ProviderName => "github";

    protected override string AuthorizationEndpoint => "https://github.com/login/oauth/authorize";
    protected override string TokenEndpoint => "https://github.com/login/oauth/access_token";
    protected override string UserInfoEndpoint => "https://api.github.com/user";
    protected override string[] DefaultScopes => new[] { "read:user", "user:email" };

    public override async Task<ExternalUserInfo> GetUserInfoAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Fetching GitHub user info");

        var userData = await FetchUserInfoJsonAsync(accessToken, cancellationToken: cancellationToken);

        var providerId = userData["id"].GetInt64().ToString()
            ?? throw new OAuthProviderError(ProviderName, "invalid_response", "User ID is missing");

        var username = userData.TryGetValue("login", out var loginElement) ? loginElement.GetString() : null;
        var name = userData.TryGetValue("name", out var nameElement) ? nameElement.GetString() : null;
        var avatarUrl = userData.TryGetValue("avatar_url", out var avatarElement) ? avatarElement.GetString() : null;

        // GitHub may not return email in the user endpoint if the email is private
        // We need to fetch it from the /user/emails endpoint if it's not available
        var email = userData.TryGetValue("email", out var emailElement) ? emailElement.GetString() : null;
        var emailVerified = false;

        if (string.IsNullOrEmpty(email))
        {
            _logger.LogDebug("Email not found in user info, fetching from /user/emails endpoint");
            var emailInfo = await FetchPrimaryEmailAsync(accessToken, cancellationToken);
            email = emailInfo.Email;
            emailVerified = emailInfo.IsVerified;
        }
        else
        {
            // If email is in the user response, GitHub considers it verified
            emailVerified = true;
        }

        var config = GetProviderConfig();
        if (config.RequireVerifiedEmail && (!emailVerified || string.IsNullOrEmpty(email)))
        {
            throw new OAuthProviderError(ProviderName, "email_not_verified",
                "Email verification is required but email is not verified by GitHub");
        }

        _logger.LogInformation("Successfully retrieved GitHub user info for user {ProviderId}", providerId);

        return new ExternalUserInfo
        {
            ProviderId = providerId,
            Email = email,
            EmailVerified = emailVerified,
            Name = name ?? username,
            GivenName = null,        // GitHub doesn't provide structured names
            FamilyName = null,       // GitHub doesn't provide structured names
            Username = username,
            ProfilePictureUrl = avatarUrl
        };
    }

    /// <summary>
    /// Fetches the user's primary email from GitHub's /user/emails endpoint.
    /// This is needed when the user's email is set to private.
    /// </summary>
    private async Task<(string? Email, bool IsVerified)> FetchPrimaryEmailAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var httpClient = _httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        httpClient.DefaultRequestHeaders.Add("User-Agent", "Pawthorize");

        try
        {
            var response = await httpClient.GetAsync("https://api.github.com/user/emails", cancellationToken);
            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Failed to fetch GitHub user emails. Status: {Status}", response.StatusCode);
                return (null, false);
            }

            var emails = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(responseContent);

            if (emails.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                // Find the primary email
                foreach (var emailObj in emails.EnumerateArray())
                {
                    var isPrimary = emailObj.TryGetProperty("primary", out var primaryProp) && primaryProp.GetBoolean();
                    if (isPrimary)
                    {
                        var emailValue = emailObj.TryGetProperty("email", out var emailProp) ? emailProp.GetString() : null;
                        var isVerified = emailObj.TryGetProperty("verified", out var verifiedProp) && verifiedProp.GetBoolean();

                        _logger.LogDebug("Found primary email from GitHub: {Email}, Verified: {IsVerified}",
                            emailValue, isVerified);

                        return (emailValue, isVerified);
                    }
                }

                // If no primary email found, try to get the first verified email
                foreach (var emailObj in emails.EnumerateArray())
                {
                    var isVerified = emailObj.TryGetProperty("verified", out var verifiedProp) && verifiedProp.GetBoolean();
                    if (isVerified)
                    {
                        var emailValue = emailObj.TryGetProperty("email", out var emailProp) ? emailProp.GetString() : null;
                        _logger.LogDebug("Found verified email from GitHub: {Email}", emailValue);
                        return (emailValue, true);
                    }
                }
            }

            _logger.LogWarning("No primary or verified email found in GitHub user emails response");
            return (null, false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching GitHub user emails");
            return (null, false);
        }
    }
}
