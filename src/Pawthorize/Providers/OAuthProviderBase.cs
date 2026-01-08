using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Models;

namespace Pawthorize.Providers;

/// <summary>
/// Base class for OAuth 2.0 providers with common functionality.
/// </summary>
public abstract class OAuthProviderBase : IExternalAuthProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly OAuthOptions _oauthOptions;
    private readonly ILogger _logger;

    protected OAuthProviderBase(
        IHttpClientFactory httpClientFactory,
        IOptions<OAuthOptions> oauthOptions,
        ILogger logger)
    {
        _httpClientFactory = httpClientFactory;
        _oauthOptions = oauthOptions.Value;
        _logger = logger;
    }

    public abstract string ProviderName { get; }

    protected abstract string AuthorizationEndpoint { get; }
    protected abstract string TokenEndpoint { get; }
    protected abstract string UserInfoEndpoint { get; }
    protected abstract string[] DefaultScopes { get; }

    protected OAuthProviderConfig GetProviderConfig()
    {
        if (!_oauthOptions.Providers.TryGetValue(ProviderName, out var config))
        {
            throw new OAuthConfigurationError(
                $"OAuth provider '{ProviderName}' is not configured.",
                "Add the provider configuration to appsettings.json or configure it in Program.cs");
        }

        if (!config.Enabled)
        {
            throw new OAuthConfigurationError(
                $"OAuth provider '{ProviderName}' is disabled.",
                "Set Enabled = true in provider configuration");
        }

        if (string.IsNullOrWhiteSpace(config.ClientId))
        {
            throw new OAuthConfigurationError(
                $"OAuth provider '{ProviderName}' is missing ClientId.",
                "Provide a valid ClientId in provider configuration");
        }

        if (string.IsNullOrWhiteSpace(config.ClientSecret))
        {
            throw new OAuthConfigurationError(
                $"OAuth provider '{ProviderName}' is missing ClientSecret.",
                "Provide a valid ClientSecret in provider configuration");
        }

        return config;
    }

    public virtual Task<string> GetAuthorizationUrlAsync(
        string state,
        string redirectUri,
        string? codeChallenge = null,
        CancellationToken cancellationToken = default)
    {
        var config = GetProviderConfig();
        var scopes = config.Scopes.Length > 0 ? config.Scopes : DefaultScopes;

        var authEndpoint = config.AuthorizationEndpoint ?? AuthorizationEndpoint;

        var queryParams = new Dictionary<string, string>
        {
            ["client_id"] = config.ClientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = string.Join(" ", scopes),
            ["state"] = state
        };

        if (!string.IsNullOrWhiteSpace(codeChallenge))
        {
            queryParams["code_challenge"] = codeChallenge;
            queryParams["code_challenge_method"] = "S256";
        }

        var queryString = string.Join("&", queryParams.Select(kvp =>
            $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));

        var authUrl = $"{authEndpoint}?{queryString}";

        _logger.LogDebug("Generated authorization URL for provider {Provider}: {Url}",
            ProviderName, authEndpoint);

        return Task.FromResult(authUrl);
    }

    public virtual async Task<OAuthToken> ExchangeCodeForTokenAsync(
        string code,
        string redirectUri,
        string? codeVerifier = null,
        CancellationToken cancellationToken = default)
    {
        var config = GetProviderConfig();
        var tokenEndpoint = config.TokenEndpoint ?? TokenEndpoint;

        _logger.LogDebug("Exchanging authorization code for access token with provider {Provider}",
            ProviderName);

        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = config.ClientId,
            ["client_secret"] = config.ClientSecret,
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["grant_type"] = "authorization_code"
        };

        if (!string.IsNullOrWhiteSpace(codeVerifier))
        {
            parameters["code_verifier"] = codeVerifier;
        }

        var httpClient = _httpClientFactory.CreateClient();
        var content = new FormUrlEncodedContent(parameters);

        try
        {
            var response = await httpClient.PostAsync(tokenEndpoint, content, cancellationToken);
            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Token exchange failed for provider {Provider}. Status: {Status}, Response: {Response}",
                    ProviderName, response.StatusCode, responseContent);

                var errorData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(responseContent);
                var error = errorData?.GetValueOrDefault("error").GetString() ?? "unknown_error";
                var errorDescription = errorData?.GetValueOrDefault("error_description").GetString();

                throw new OAuthProviderError(ProviderName, error, errorDescription);
            }

            var tokenData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(responseContent)
                ?? throw new OAuthProviderError(ProviderName, "invalid_response", "Token response is invalid");

            _logger.LogInformation("Successfully exchanged authorization code for access token with provider {Provider}",
                ProviderName);

            return new OAuthToken
            {
                AccessToken = tokenData["access_token"].GetString()
                    ?? throw new OAuthProviderError(ProviderName, "invalid_response", "Access token is missing"),
                RefreshToken = tokenData.TryGetValue("refresh_token", out var rt) ? rt.GetString() : null,
                TokenType = tokenData.TryGetValue("token_type", out var tt) ? tt.GetString() : "Bearer",
                ExpiresIn = tokenData.TryGetValue("expires_in", out var ei) ? ei.GetInt32() : null,
                Scope = tokenData.TryGetValue("scope", out var s) ? s.GetString() : null
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP request failed during token exchange with provider {Provider}", ProviderName);
            throw new OAuthProviderError(ProviderName, "network_error", ex.Message);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Failed to parse token response from provider {Provider}", ProviderName);
            throw new OAuthProviderError(ProviderName, "invalid_response", ex.Message);
        }
    }

    public abstract Task<ExternalUserInfo> GetUserInfoAsync(
        string accessToken,
        CancellationToken cancellationToken = default);

    protected async Task<Dictionary<string, JsonElement>> FetchUserInfoJsonAsync(
        string accessToken,
        string? userInfoEndpoint = null,
        CancellationToken cancellationToken = default)
    {
        var config = GetProviderConfig();
        var endpoint = userInfoEndpoint ?? config.UserInfoEndpoint ?? UserInfoEndpoint;

        _logger.LogDebug("Fetching user info from provider {Provider} at {Endpoint}",
            ProviderName, endpoint);

        var httpClient = _httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        try
        {
            var response = await httpClient.GetAsync(endpoint, cancellationToken);
            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("User info request failed for provider {Provider}. Status: {Status}, Response: {Response}",
                    ProviderName, response.StatusCode, responseContent);

                throw new OAuthProviderError(ProviderName, "user_info_error",
                    $"Failed to fetch user info: {response.StatusCode}");
            }

            var userData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(responseContent)
                ?? throw new OAuthProviderError(ProviderName, "invalid_response", "User info response is invalid");

            _logger.LogInformation("Successfully fetched user info from provider {Provider}", ProviderName);

            return userData;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP request failed while fetching user info from provider {Provider}", ProviderName);
            throw new OAuthProviderError(ProviderName, "network_error", ex.Message);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Failed to parse user info response from provider {Provider}", ProviderName);
            throw new OAuthProviderError(ProviderName, "invalid_response", ex.Message);
        }
    }
}
