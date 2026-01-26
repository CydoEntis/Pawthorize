namespace Pawthorize.Internal;

/// <summary>
/// Internal helper for splitting full names into first/last components.
/// Used when OAuth providers don't provide structured names.
/// </summary>
internal static class NameHelper
{
    /// <summary>
    /// Splits full name on first space.
    /// Examples:
    ///   "John Doe" → ("John", "Doe")
    ///   "Mary Jane Smith" → ("Mary", "Jane Smith")
    ///   "Madonna" → ("Madonna", "")
    ///   null → ("", "")
    /// </summary>
    /// <param name="fullName">The full name to split</param>
    /// <returns>Tuple of (firstName, lastName)</returns>
    public static (string firstName, string lastName) SplitName(string? fullName)
    {
        if (string.IsNullOrWhiteSpace(fullName))
        {
            return (string.Empty, string.Empty);
        }

        var trimmed = fullName.Trim();
        var firstSpaceIndex = trimmed.IndexOf(' ');

        if (firstSpaceIndex == -1)
        {
            // No space - treat entire string as first name
            return (trimmed, string.Empty);
        }

        var firstName = trimmed.Substring(0, firstSpaceIndex).Trim();
        var lastName = trimmed.Substring(firstSpaceIndex + 1).Trim();

        return (firstName, lastName);
    }
}
