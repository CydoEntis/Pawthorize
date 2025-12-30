using Microsoft.AspNetCore.Builder;
using Pawthorize.Middleware;

namespace Pawthorize.Extensions;

/// <summary>
/// Extension methods for configuring Pawthorize middleware in the application pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Explicitly add Pawthorize CSRF protection middleware.
    ///
    /// NOTE: This method is OPTIONAL. CSRF protection is automatically enabled by UsePawthorize()
    /// when TokenDelivery is set to Hybrid or HttpOnlyCookies and Csrf.Enabled is true.
    ///
    /// Only use this method if you need to manually control CSRF middleware registration
    /// (e.g., custom middleware ordering scenarios).
    ///
    /// This middleware automatically validates CSRF tokens for state-changing requests
    /// when using HttpOnlyCookies or Hybrid token delivery modes.
    /// </summary>
    /// <param name="app">Application builder</param>
    /// <returns>Application builder for chaining</returns>
    /// <example>
    /// // Standard usage (CSRF auto-enabled):
    /// app.UsePawthorize();
    ///
    /// // Advanced usage (manual control):
    /// app.UseErrorHound();
    /// app.UsePawthorizeCsrf(); // Explicit CSRF
    /// app.UseAuthentication();
    /// app.UseAuthorization();
    /// </example>
    public static IApplicationBuilder UsePawthorizeCsrf(this IApplicationBuilder app)
    {
        return app.UseMiddleware<CsrfProtectionMiddleware>();
    }
}
