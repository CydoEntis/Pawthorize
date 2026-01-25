using ErrorHound.BuiltIn;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Services;

namespace Pawthorize.Middleware;

/// <summary>
/// Middleware for validating CSRF tokens on state-changing requests.
/// Automatically validates requests when using HttpOnlyCookies or Hybrid token delivery.
/// </summary>
public class CsrfProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly PawthorizeOptions _options;
    private readonly ILogger<CsrfProtectionMiddleware> _logger;

    // HTTP methods that require CSRF protection
    private static readonly HashSet<string> ProtectedMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "POST", "PUT", "DELETE", "PATCH"
    };

    // Pawthorize endpoint names that are excluded from CSRF validation
    // (Login and register don't have CSRF tokens yet)
    private static readonly HashSet<string> ExcludedEndpointNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Login",           // User doesn't have CSRF token yet
        "Register",        // User doesn't have CSRF token yet
        "ForgotPassword",  // Public endpoint, no auth required
        "ResetPassword",   // Protected by email token, no session/CSRF
        "VerifyEmail"      // Protected by email token, no session/CSRF
    };

    public CsrfProtectionMiddleware(
        RequestDelegate next,
        IOptions<PawthorizeOptions> options,
        ILogger<CsrfProtectionMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, CsrfTokenService csrfService)
    {
        // Skip validation if CSRF is disabled
        if (!_options.Csrf.Enabled)
        {
            _logger.LogDebug("CSRF protection is disabled, skipping validation");
            await _next(context);
            return;
        }

        // Skip validation if not using cookies
        if (_options.TokenDelivery == TokenDeliveryStrategy.ResponseBody)
        {
            _logger.LogDebug("Token delivery is ResponseBody, skipping CSRF validation");
            await _next(context);
            return;
        }

        // Only validate state-changing methods
        if (!ProtectedMethods.Contains(context.Request.Method))
        {
            _logger.LogDebug("Request method {Method} does not require CSRF validation", context.Request.Method);
            await _next(context);
            return;
        }

        // Skip validation for excluded endpoints (check endpoint name from routing)
        var endpoint = context.GetEndpoint();
        var path = context.Request.Path.Value ?? "";

        if (IsExcludedEndpoint(endpoint, path))
        {
            var endpointName = endpoint?.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.EndpointNameMetadata>()?.EndpointName;
            _logger.LogDebug("Endpoint {EndpointName} at path {Path} is excluded from CSRF validation", endpointName ?? "Unknown", path);
            await _next(context);
            return;
        }

        // Validate CSRF token
        var cookieToken = context.Request.Cookies[_options.Csrf.CookieName];
        var headerToken = context.Request.Headers[_options.Csrf.HeaderName].FirstOrDefault();

        _logger.LogDebug("Validating CSRF token for {Method} {Path}", context.Request.Method, path);

        // Check for missing cookie
        if (string.IsNullOrEmpty(cookieToken))
        {
            _logger.LogWarning(
                "CSRF validation failed for {Method} {Path}. Reason: Missing CSRF cookie '{CookieName}'",
                context.Request.Method,
                path,
                _options.Csrf.CookieName);

            throw new CsrfValidationError(
                reason: $"Missing CSRF cookie '{_options.Csrf.CookieName}'",
                cookieName: _options.Csrf.CookieName,
                headerName: _options.Csrf.HeaderName);
        }

        // Check for missing header
        if (string.IsNullOrEmpty(headerToken))
        {
            _logger.LogWarning(
                "CSRF validation failed for {Method} {Path}. Reason: Missing CSRF header '{HeaderName}'",
                context.Request.Method,
                path,
                _options.Csrf.HeaderName);

            throw new CsrfValidationError(
                reason: $"Missing CSRF header '{_options.Csrf.HeaderName}'",
                cookieName: _options.Csrf.CookieName,
                headerName: _options.Csrf.HeaderName);
        }

        // Validate tokens match (constant-time comparison)
        if (!csrfService.ValidateToken(cookieToken, headerToken))
        {
            _logger.LogWarning(
                "CSRF validation failed for {Method} {Path}. Reason: CSRF token mismatch. Cookie and header values do not match.",
                context.Request.Method,
                path);

            throw new CsrfValidationError(
                reason: "CSRF token mismatch. The cookie value does not match the header value.",
                cookieName: _options.Csrf.CookieName,
                headerName: _options.Csrf.HeaderName);
        }

        _logger.LogDebug("CSRF validation successful for {Method} {Path}", context.Request.Method, path);

        await _next(context);
    }

    /// <summary>
    /// Check if the endpoint is excluded from CSRF validation.
    /// Checks both endpoint name (from routing metadata) and custom excluded paths.
    /// </summary>
    private bool IsExcludedEndpoint(Endpoint? endpoint, string path)
    {
        // Check Pawthorize endpoint names (works regardless of custom path configuration)
        if (endpoint != null)
        {
            var endpointName = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.EndpointNameMetadata>()?.EndpointName;
            if (endpointName != null && ExcludedEndpointNames.Contains(endpointName))
            {
                return true;
            }
        }

        // Check custom excluded paths from configuration (for user's custom endpoints)
        foreach (var excludedPath in _options.Csrf.ExcludedPaths)
        {
            if (path.Equals(excludedPath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
