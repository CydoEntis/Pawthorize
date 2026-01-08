using System.Net;

namespace Pawthorize.Errors;

/// <summary>
/// Thrown when OAuth provider API returns an error.
/// Returns 502 Bad Gateway.
/// </summary>
public sealed class OAuthProviderError : OAuthError
{
    public OAuthProviderError(string provider, string error, string? errorDescription = null)
        : base(
            code: "OAUTH_PROVIDER_ERROR",
            message: $"OAuth provider '{provider}' returned error: {error}",
            status: (int)HttpStatusCode.BadGateway,
            details: errorDescription)
    {
        Provider = provider;
        ProviderError = error;
        ErrorDescription = errorDescription;
    }

    public string Provider { get; }
    public string ProviderError { get; }
    public string? ErrorDescription { get; }
}
