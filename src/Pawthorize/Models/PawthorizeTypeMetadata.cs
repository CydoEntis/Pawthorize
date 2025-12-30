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

    public PawthorizeTypeMetadata(Type userType, Type registerRequestType)
    {
        UserType = userType ?? throw new ArgumentNullException(nameof(userType));
        RegisterRequestType = registerRequestType ?? throw new ArgumentNullException(nameof(registerRequestType));
    }
}
