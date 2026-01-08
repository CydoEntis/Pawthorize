namespace Pawthorize.Models;

/// <summary>
/// Stores type metadata for Pawthorize generic parameters.
/// This allows non-generic methods to retrieve the user and registration request types
/// that were configured during AddPawthorize.
/// </summary>
internal sealed class PawthorizeTypeMetadata
{
    /// <summary>
    /// The user type (TUser) that implements IAuthenticatedUser.
    /// </summary>
    public Type UserType { get; }

    /// <summary>
    /// The registration request type (TRegisterRequest) that extends RegisterRequest.
    /// </summary>
    public Type RegisterRequestType { get; }

    /// <summary>
    /// Indicates whether OAuth is enabled via options.AddGoogle()/AddDiscord() etc.
    /// </summary>
    public bool EnableOAuth { get; }

    public PawthorizeTypeMetadata(Type userType, Type registerRequestType, bool enableOAuth = false)
    {
        UserType = userType ?? throw new ArgumentNullException(nameof(userType));
        RegisterRequestType = registerRequestType ?? throw new ArgumentNullException(nameof(registerRequestType));
        EnableOAuth = enableOAuth;
    }
}
