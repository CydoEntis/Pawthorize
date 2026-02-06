using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Pawthorize.Configuration;
using Pawthorize.Services;
using System.Text.Json;
using Xunit;

namespace Pawthorize.Tests.Services;

public class RateLimitingServiceTests
{
    private readonly Mock<ILogger<RateLimitingService>> _mockLogger;
    private readonly RateLimitingService _service;

    public RateLimitingServiceTests()
    {
        _mockLogger = new Mock<ILogger<RateLimitingService>>();
        _mockLogger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
        _service = new RateLimitingService(_mockLogger.Object);
    }

    #region ValidateConfiguration

    [Fact]
    public void ValidateConfiguration_WithValidOptions_ShouldNotThrow()
    {
        var options = CreateValidOptions();

        Action act = () => _service.ValidateConfiguration(options);

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateConfiguration_WithNullOptions_ShouldThrowArgumentNullException()
    {
        Action act = () => _service.ValidateConfiguration(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void ValidateConfiguration_WithInvalidGlobalPermitLimit_ShouldThrowArgumentException(int permitLimit)
    {
        var options = CreateValidOptions();
        options.Global.PermitLimit = permitLimit;

        Action act = () => _service.ValidateConfiguration(options);

        act.Should().Throw<ArgumentException>().WithMessage("*Global*PermitLimit*");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void ValidateConfiguration_WithInvalidLoginPermitLimit_ShouldThrowArgumentException(int permitLimit)
    {
        var options = CreateValidOptions();
        options.Login.PermitLimit = permitLimit;

        Action act = () => _service.ValidateConfiguration(options);

        act.Should().Throw<ArgumentException>().WithMessage("*Login*PermitLimit*");
    }

    [Fact]
    public void ValidateConfiguration_WithZeroRegisterWindow_ShouldThrowArgumentException()
    {
        var options = CreateValidOptions();
        options.Register.Window = TimeSpan.Zero;

        Action act = () => _service.ValidateConfiguration(options);

        act.Should().Throw<ArgumentException>().WithMessage("*Register*Window*");
    }

    [Fact]
    public void ValidateConfiguration_WithNegativePasswordResetWindow_ShouldThrowArgumentException()
    {
        var options = CreateValidOptions();
        options.PasswordReset.Window = TimeSpan.FromMinutes(-5);

        Action act = () => _service.ValidateConfiguration(options);

        act.Should().Throw<ArgumentException>().WithMessage("*PasswordReset*Window*");
    }

    [Fact]
    public void ValidateConfiguration_WithInvalidCustomPolicy_ShouldThrowArgumentException()
    {
        var options = CreateValidOptions();
        options.CustomPolicies["my-endpoint"] = new RateLimitPolicy
        {
            PermitLimit = 0,
            Window = TimeSpan.FromMinutes(1)
        };

        Action act = () => _service.ValidateConfiguration(options);

        act.Should().Throw<ArgumentException>().WithMessage("*Custom:my-endpoint*PermitLimit*");
    }

    [Fact]
    public void ValidateConfiguration_WithInvalidCustomPolicyWindow_ShouldThrowArgumentException()
    {
        var options = CreateValidOptions();
        options.CustomPolicies["my-endpoint"] = new RateLimitPolicy
        {
            PermitLimit = 10,
            Window = TimeSpan.Zero
        };

        Action act = () => _service.ValidateConfiguration(options);

        act.Should().Throw<ArgumentException>().WithMessage("*Custom:my-endpoint*Window*");
    }

    [Fact]
    public void ValidateConfiguration_WithTokenBucketStrategy_AndMissingTokensPerPeriod_ShouldLogWarning()
    {
        var options = CreateValidOptions();
        options.Strategy = RateLimitingStrategy.TokenBucket;
        // TokensPerPeriod and ReplenishmentPeriod intentionally left null

        _service.ValidateConfiguration(options);

        // Warning fires once per policy that's missing the required fields — 6 standard policies
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, _) => v.ToString()!.Contains("TokenBucket")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Exactly(6));
    }

    [Fact]
    public void ValidateConfiguration_WithTokenBucketStrategy_AndTokensPerPeriodSet_ShouldNotLogWarning()
    {
        var options = CreateValidOptions();
        options.Strategy = RateLimitingStrategy.TokenBucket;

        // Set TokensPerPeriod and ReplenishmentPeriod on all policies
        foreach (var policy in new[] { options.Global, options.Login, options.Register, options.PasswordReset, options.Refresh, options.OAuth })
        {
            policy.TokensPerPeriod = 10;
            policy.ReplenishmentPeriod = TimeSpan.FromSeconds(6);
        }

        _service.ValidateConfiguration(options);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, _) => v.ToString()!.Contains("TokenBucket")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Never);
    }

    #endregion

    #region ConfigureRateLimiting

    [Fact]
    public void ConfigureRateLimiting_WhenDisabled_ShouldNotAddServices()
    {
        var services = new ServiceCollection();
        var initialCount = services.Count;
        var options = CreateValidOptions();
        options.Enabled = false;

        _service.ConfigureRateLimiting(services, options);

        services.Count.Should().Be(initialCount);
    }

    [Fact]
    public void ConfigureRateLimiting_WhenDisabled_ShouldLogInformation()
    {
        var services = new ServiceCollection();
        var options = CreateValidOptions();
        options.Enabled = false;

        _service.ConfigureRateLimiting(services, options);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, _) => v.ToString()!.Contains("Rate limiting is disabled")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void ConfigureRateLimiting_WhenEnabled_ShouldAddServices()
    {
        var services = new ServiceCollection();
        var initialCount = services.Count;
        var options = CreateValidOptions();

        _service.ConfigureRateLimiting(services, options);

        services.Count.Should().BeGreaterThan(initialCount);
    }

    [Fact]
    public void ConfigureRateLimiting_WhenEnabled_WithCustomPolicies_ShouldNotThrow()
    {
        var services = new ServiceCollection();
        var options = CreateValidOptions();
        options.CustomPolicies["custom-endpoint"] = new RateLimitPolicy
        {
            PermitLimit = 20,
            Window = TimeSpan.FromMinutes(10)
        };

        Action act = () => _service.ConfigureRateLimiting(services, options);

        act.Should().NotThrow();
    }

    #endregion

    #region BuildRateLimitedResponse

    [Fact]
    public void BuildRateLimitedResponse_ShouldReturnCorrectStructure()
    {
        var response = RateLimitingService.BuildRateLimitedResponse(60);
        var json = JsonSerializer.Serialize(response);
        var parsed = JsonDocument.Parse(json).RootElement;

        parsed.GetProperty("success").GetBoolean().Should().BeFalse();
        parsed.GetProperty("error").GetProperty("code").GetString().Should().Be("RATE_LIMITED");
        parsed.GetProperty("error").GetProperty("message").GetString().Should().Be("Too many requests. Please try again later.");
        parsed.GetProperty("error").GetProperty("details").GetProperty("retryAfter").GetInt32().Should().Be(60);
        parsed.GetProperty("meta").GetProperty("version").GetString().Should().Be("v1.0");
        parsed.GetProperty("meta").GetProperty("timestamp").GetString().Should().NotBeNull();
    }

    [Theory]
    [InlineData(30)]
    [InlineData(60)]
    [InlineData(120)]
    [InlineData(300)]
    public void BuildRateLimitedResponse_WithDifferentRetryAfterValues_ShouldReflectValue(int retryAfter)
    {
        var response = RateLimitingService.BuildRateLimitedResponse(retryAfter);
        var json = JsonSerializer.Serialize(response);
        var parsed = JsonDocument.Parse(json).RootElement;

        parsed.GetProperty("error").GetProperty("details").GetProperty("retryAfter").GetInt32().Should().Be(retryAfter);
    }

    [Fact]
    public void BuildRateLimitedResponse_TimestampShouldBeValidUtcDateTime()
    {
        var before = DateTimeOffset.UtcNow;
        var response = RateLimitingService.BuildRateLimitedResponse(60);
        var after = DateTimeOffset.UtcNow;

        var json = JsonSerializer.Serialize(response);
        var parsed = JsonDocument.Parse(json).RootElement;
        var timestamp = parsed.GetProperty("meta").GetProperty("timestamp").GetString()!;

        DateTimeOffset.TryParse(timestamp, out var parsedDate).Should().BeTrue();
        parsedDate.Should().BeOnOrAfter(before);
        parsedDate.Should().BeOnOrBefore(after);
    }

    [Fact]
    public void BuildRateLimitedResponse_ShouldMatchPawthorizeErrorFormatterShape()
    {
        // Verify the rate limit response has the same top-level shape as PawthorizeErrorFormatter output:
        // { success, error: { code, message, details }, meta: { timestamp, version } }
        var response = RateLimitingService.BuildRateLimitedResponse(60);
        var json = JsonSerializer.Serialize(response);
        var parsed = JsonDocument.Parse(json).RootElement;

        // Top-level keys
        parsed.EnumerateObject().Select(p => p.Name)
            .Should().BeEquivalentTo(new[] { "success", "error", "meta" });

        // error keys
        parsed.GetProperty("error").EnumerateObject().Select(p => p.Name)
            .Should().BeEquivalentTo(new[] { "code", "message", "details" });

        // meta keys
        parsed.GetProperty("meta").EnumerateObject().Select(p => p.Name)
            .Should().BeEquivalentTo(new[] { "timestamp", "version" });
    }

    #endregion

    private static PawthorizeRateLimitingOptions CreateValidOptions()
    {
        return new PawthorizeRateLimitingOptions
        {
            Enabled = true,
            Strategy = RateLimitingStrategy.FixedWindow,
            PartitionBy = RateLimitPartitionBy.IpAddress,
            Global = new RateLimitPolicy { PermitLimit = 100, Window = TimeSpan.FromMinutes(1) },
            Login = new RateLimitPolicy { PermitLimit = 5, Window = TimeSpan.FromMinutes(5) },
            Register = new RateLimitPolicy { PermitLimit = 3, Window = TimeSpan.FromMinutes(15) },
            PasswordReset = new RateLimitPolicy { PermitLimit = 3, Window = TimeSpan.FromMinutes(15) },
            Refresh = new RateLimitPolicy { PermitLimit = 50, Window = TimeSpan.FromMinutes(5) },
            OAuth = new RateLimitPolicy { PermitLimit = 10, Window = TimeSpan.FromMinutes(5) }
        };
    }
}
