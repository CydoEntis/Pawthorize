using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SuccessHound.Extensions;

namespace Pawthorize.Tests.Helpers;

/// <summary>
/// Helper for creating properly configured HttpContext instances in tests.
/// </summary>
public static class HttpContextTestHelper
{
    /// <summary>
    /// Create an HttpContext with SuccessHound services configured.
    /// </summary>
    public static HttpContext CreateHttpContext()
    {
        var services = new ServiceCollection();

        // Find and use SuccessHound's default formatter
        Type? defaultFormatterType = null;
        var possibleTypes = new[]
        {
            "SuccessHound.Defaults.DefaultSuccessFormatter, SuccessHound",
            "SuccessHound.Formatters.DefaultSuccessFormatter, SuccessHound",
            "SuccessHound.DefaultSuccessFormatter, SuccessHound"
        };

        foreach (var typeName in possibleTypes)
        {
            defaultFormatterType = Type.GetType(typeName);
            if (defaultFormatterType != null)
                break;
        }

        if (defaultFormatterType == null)
        {
            throw new InvalidOperationException(
                "Could not find SuccessHound's DefaultSuccessFormatter for tests. " +
                "Make sure SuccessHound package is installed.");
        }

        // Use reflection to call AddSuccessHound with the formatter
        var addSuccessHoundMethod = typeof(SuccessHoundExtensions)
            .GetMethods()
            .FirstOrDefault(m => m.Name == "AddSuccessHound" && m.GetParameters().Length == 2);

        if (addSuccessHoundMethod != null)
        {
            var optionsParam = System.Linq.Expressions.Expression.Parameter(
                addSuccessHoundMethod.GetParameters()[1].ParameterType.GetGenericArguments()[0], "options");

            var useFormatterMethod = optionsParam.Type
                .GetMethod("UseFormatter")
                ?.MakeGenericMethod(defaultFormatterType);

            if (useFormatterMethod != null)
            {
                var callExpression = System.Linq.Expressions.Expression.Call(
                    optionsParam, useFormatterMethod);

                var lambda = System.Linq.Expressions.Expression.Lambda(
                    callExpression, optionsParam);

                var configAction = lambda.Compile();

                addSuccessHoundMethod.Invoke(null, new object[] { services, configAction });

                var serviceProvider = services.BuildServiceProvider();

                var httpContext = new DefaultHttpContext
                {
                    RequestServices = serviceProvider
                };

                // Set request as HTTPS for proper cookie security testing
                httpContext.Request.Scheme = "https";

                return httpContext;
            }
        }

        throw new InvalidOperationException(
            "Could not configure SuccessHound for tests.");
    }
}
