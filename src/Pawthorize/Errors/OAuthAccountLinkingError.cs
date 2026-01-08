using System.Net;

namespace Pawthorize.Errors;

/// <summary>
/// Thrown when account linking encounters a conflict.
/// Returns 409 Conflict.
/// </summary>
public sealed class OAuthAccountLinkingError : OAuthError
{
    private OAuthAccountLinkingError(string message, string? details = null)
        : base(
            code: "OAUTH_LINKING_ERROR",
            message: message,
            status: (int)HttpStatusCode.Conflict,
            details: details)
    {
    }

    public static OAuthAccountLinkingError ProviderAlreadyLinked(string provider) =>
        new($"The {provider} account is already linked to another user.");

    public static OAuthAccountLinkingError CannotUnlinkLastMethod() =>
        new("Cannot unlink the last authentication method. Add a password or link another provider first.");

    public static OAuthAccountLinkingError ProviderAlreadyLinkedToCurrentUser(string provider) =>
        new($"The {provider} account is already linked to your account.");
}
