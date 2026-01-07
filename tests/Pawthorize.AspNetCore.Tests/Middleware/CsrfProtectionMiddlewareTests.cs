using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Errors;
using Pawthorize.Middleware;
using Pawthorize.Models;
using Pawthorize.Services;
using Xunit;

namespace Pawthorize.AspNetCore.Tests.Middleware;

public class CsrfProtectionMiddlewareTests
{
    private readonly Mock<ILogger<CsrfProtectionMiddleware>> _mockLogger;
    private readonly Mock<ILogger<CsrfTokenService>> _mockCsrfLogger;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly PawthorizeOptions _options;
    private readonly CsrfTokenService _csrfService;
    private bool _nextCalled;

    public CsrfProtectionMiddlewareTests()
    {
        _mockLogger = new Mock<ILogger<CsrfProtectionMiddleware>>();
        _mockCsrfLogger = new Mock<ILogger<CsrfTokenService>>();
        _csrfService = new CsrfTokenService(_mockCsrfLogger.Object);

        _options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.Hybrid,
            Csrf = new CsrfOptions
            {
                Enabled = true,
                CookieName = "XSRF-TOKEN",
                HeaderName = "X-XSRF-TOKEN",
                TokenLifetimeMinutes = 10080
            }
        };

        _mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        _mockOptions.Setup(o => o.Value).Returns(_options);

        _nextCalled = false;
    }

    private RequestDelegate CreateNextDelegate()
    {
        return context =>
        {
            _nextCalled = true;
            return Task.CompletedTask;
        };
    }

    private HttpContext CreateHttpContext(string method, string path)
    {
        var httpContext = HttpContextTestHelper.CreateHttpContext();
        httpContext.Request.Method = method;
        httpContext.Request.Path = path;
        return httpContext;
    }

    private void AddCookie(HttpContext context, string key, string value)
    {
        // Use reflection to set cookies for testing
        var cookieCollection = new Dictionary<string, string> { [key] = value };
        var requestFeature = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>();

        if (requestFeature != null)
        {
            // Build cookie string
            context.Request.Headers["Cookie"] = $"{key}={value}";
        }
    }

    [Fact]
    public async Task InvokeAsync_WhenCsrfDisabled_ShouldSkipValidation()
    {
        // Arrange
        _options.Csrf.Enabled = false;
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_WhenTokenDeliveryIsResponseBody_ShouldSkipValidation()
    {
        // Arrange
        _options.TokenDelivery = TokenDeliveryStrategy.ResponseBody;
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    [InlineData("TRACE")]
    public async Task InvokeAsync_ForSafeMethods_ShouldSkipValidation(string method)
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext(method, "/api/auth/user");

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Theory]
    [InlineData("/api/auth/login")]
    [InlineData("/api/auth/register")]
    [InlineData("/api/auth/forgot-password")]
    [InlineData("/api/auth/reset-password")]
    [InlineData("/api/auth/verify-email")]
    public async Task InvokeAsync_ForExcludedEndpoints_ShouldSkipValidation(string path)
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", path);

        // Simulate endpoint routing metadata for excluded endpoints
        var endpointName = path.Split('/').Last();
        endpointName = char.ToUpper(endpointName[0]) + endpointName.Substring(1);
        if (endpointName.Contains("-"))
        {
            var parts = endpointName.Split('-');
            endpointName = string.Join("", parts.Select(p => char.ToUpper(p[0]) + p.Substring(1)));
        }

        var endpointMetadata = new EndpointMetadataCollection(new EndpointNameMetadata(endpointName));
        var endpoint = new Endpoint(c => Task.CompletedTask, endpointMetadata, endpointName);
        context.SetEndpoint(endpoint);

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_WithMissingCookie_ShouldThrowCsrfValidationErrorWithSpecificReason()
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Add header but no cookie
        context.Request.Headers["X-XSRF-TOKEN"] = "test-token";

        // Act & Assert
        var exception = await Assert.ThrowsAsync<CsrfValidationError>(
            () => middleware.InvokeAsync(context, _csrfService));

        exception.Code.Should().Be("CSRF_VALIDATION_FAILED");
        exception.Message.Should().Be("CSRF token validation failed");

        // Verify details contain the specific reason
        var details = exception.Details;
        details.Should().NotBeNull();

        var reasonProp = details!.GetType().GetProperty("reason");
        var reason = reasonProp?.GetValue(details)?.ToString() ?? "";
        reason.Should().Contain("Missing CSRF cookie");
        reason.Should().Contain("XSRF-TOKEN");

        _nextCalled.Should().BeFalse();
    }

    [Fact]
    public async Task InvokeAsync_WithMissingHeader_ShouldThrowCsrfValidationErrorWithSpecificReason()
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Add cookie but no header
        AddCookie(context, "XSRF-TOKEN", "test-token");

        // Act & Assert
        var exception = await Assert.ThrowsAsync<CsrfValidationError>(
            () => middleware.InvokeAsync(context, _csrfService));

        exception.Code.Should().Be("CSRF_VALIDATION_FAILED");
        exception.Message.Should().Be("CSRF token validation failed");

        // Verify details contain the specific reason
        var details = exception.Details;
        details.Should().NotBeNull();

        var reasonProp = details!.GetType().GetProperty("reason");
        var reason = reasonProp?.GetValue(details)?.ToString() ?? "";
        reason.Should().Contain("Missing CSRF header");
        reason.Should().Contain("X-XSRF-TOKEN");

        _nextCalled.Should().BeFalse();
    }

    [Fact]
    public async Task InvokeAsync_WithMismatchedTokens_ShouldThrowCsrfValidationErrorWithSpecificReason()
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Add mismatched cookie and header
        AddCookie(context, "XSRF-TOKEN", "cookie-token");
        context.Request.Headers["X-XSRF-TOKEN"] = "different-header-token";

        // Act & Assert
        var exception = await Assert.ThrowsAsync<CsrfValidationError>(
            () => middleware.InvokeAsync(context, _csrfService));

        exception.Code.Should().Be("CSRF_VALIDATION_FAILED");
        exception.Message.Should().Be("CSRF token validation failed");

        // Verify details contain the specific reason
        var details = exception.Details;
        details.Should().NotBeNull();

        var reasonProp = details!.GetType().GetProperty("reason");
        var reason = reasonProp?.GetValue(details)?.ToString() ?? "";
        reason.Should().Contain("CSRF token mismatch");
        reason.Should().Contain("does not match");

        _nextCalled.Should().BeFalse();
    }

    [Fact]
    public async Task InvokeAsync_WithMatchingTokens_ShouldPassValidation()
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Add matching cookie and header
        var token = "matching-token-value";
        AddCookie(context, "XSRF-TOKEN", token);
        context.Request.Headers["X-XSRF-TOKEN"] = token;

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public async Task InvokeAsync_ForStateChangingMethods_WithValidToken_ShouldPassValidation(string method)
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext(method, "/api/auth/refresh");

        // Add matching cookie and header
        var token = "valid-token";
        AddCookie(context, "XSRF-TOKEN", token);
        context.Request.Headers["X-XSRF-TOKEN"] = token;

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_WithCustomExcludedPath_ShouldSkipValidation()
    {
        // Arrange
        _options.Csrf.ExcludedPaths = new List<string> { "/api/custom/webhook" };
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/custom/webhook");

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_ErrorDetails_ShouldIncludeActionableHints()
    {
        // Arrange
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Act & Assert
        var exception = await Assert.ThrowsAsync<CsrfValidationError>(
            () => middleware.InvokeAsync(context, _csrfService));

        // Verify error code and message
        exception.Code.Should().Be("CSRF_VALIDATION_FAILED");
        exception.Message.Should().Be("CSRF token validation failed");

        // Verify error details include actionable information
        var details = exception.Details;
        details.Should().NotBeNull();

        // Use reflection to access properties of the anonymous object
        var detailsType = details!.GetType();
        var cookieNameProp = detailsType.GetProperty("cookieName");
        var headerNameProp = detailsType.GetProperty("headerName");
        var hintProp = detailsType.GetProperty("hint");
        var exampleProp = detailsType.GetProperty("example");
        var documentationProp = detailsType.GetProperty("documentation");

        cookieNameProp?.GetValue(details)?.ToString().Should().Be("XSRF-TOKEN");
        headerNameProp?.GetValue(details)?.ToString().Should().Be("X-XSRF-TOKEN");

        var hint = hintProp?.GetValue(details)?.ToString();
        hint.Should().Contain("Read the CSRF token");
        hint.Should().Contain("include it in the");
        hint.Should().Contain("request header");

        exampleProp?.GetValue(details)?.ToString().Should().Contain("X-XSRF-TOKEN:");
        documentationProp?.GetValue(details)?.ToString().Should().Contain("state-changing requests");
    }

    [Fact]
    public async Task InvokeAsync_WithCustomCookieAndHeaderNames_ShouldValidateCorrectly()
    {
        // Arrange
        _options.Csrf.CookieName = "Custom-CSRF-Cookie";
        _options.Csrf.HeaderName = "X-Custom-CSRF-Header";
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Add matching custom cookie and header
        var token = "custom-token";
        AddCookie(context, "Custom-CSRF-Cookie", token);
        context.Request.Headers["X-Custom-CSRF-Header"] = token;

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_WithHttpOnlyCookiesMode_ShouldValidate()
    {
        // Arrange
        _options.TokenDelivery = TokenDeliveryStrategy.HttpOnlyCookies;
        var middleware = new CsrfProtectionMiddleware(CreateNextDelegate(), _mockOptions.Object, _mockLogger.Object);
        var context = CreateHttpContext("POST", "/api/auth/refresh");

        // Add matching cookie and header
        var token = "token-value";
        AddCookie(context, "XSRF-TOKEN", token);
        context.Request.Headers["X-XSRF-TOKEN"] = token;

        // Act
        await middleware.InvokeAsync(context, _csrfService);

        // Assert
        _nextCalled.Should().BeTrue();
    }
}
