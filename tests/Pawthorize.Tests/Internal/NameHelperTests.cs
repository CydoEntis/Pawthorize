using FluentAssertions;
using Pawthorize.Internal;
using Xunit;

namespace Pawthorize.Tests.Internal;

public class NameHelperTests
{
    [Fact]
    public void SplitName_WithFirstAndLastName_ShouldSplitCorrectly()
    {
        var (firstName, lastName) = NameHelper.SplitName("John Doe");

        firstName.Should().Be("John");
        lastName.Should().Be("Doe");
    }

    [Fact]
    public void SplitName_WithSingleName_ShouldReturnNameAsFirstNameAndEmptyLastName()
    {
        var (firstName, lastName) = NameHelper.SplitName("Madonna");

        firstName.Should().Be("Madonna");
        lastName.Should().Be("");
    }

    [Fact]
    public void SplitName_WithMultipleSpaces_ShouldSplitOnFirstSpace()
    {
        var (firstName, lastName) = NameHelper.SplitName("Mary Jane Smith");

        firstName.Should().Be("Mary");
        lastName.Should().Be("Jane Smith");
    }

    [Fact]
    public void SplitName_WithNull_ShouldReturnEmptyStrings()
    {
        var (firstName, lastName) = NameHelper.SplitName(null);

        firstName.Should().Be("");
        lastName.Should().Be("");
    }

    [Fact]
    public void SplitName_WithWhitespace_ShouldReturnEmptyStrings()
    {
        var (firstName, lastName) = NameHelper.SplitName("  ");

        firstName.Should().Be("");
        lastName.Should().Be("");
    }

    [Fact]
    public void SplitName_WithEmptyString_ShouldReturnEmptyStrings()
    {
        var (firstName, lastName) = NameHelper.SplitName("");

        firstName.Should().Be("");
        lastName.Should().Be("");
    }

    [Fact]
    public void SplitName_WithLeadingAndTrailingSpaces_ShouldTrimAndSplit()
    {
        var (firstName, lastName) = NameHelper.SplitName("  John Doe  ");

        firstName.Should().Be("John");
        lastName.Should().Be("Doe");
    }

    [Fact]
    public void SplitName_WithExtraSpacesBetween_ShouldHandleCorrectly()
    {
        var (firstName, lastName) = NameHelper.SplitName("John  Doe");

        firstName.Should().Be("John");
        lastName.Should().Be("Doe");
    }

    [Fact]
    public void SplitName_WithMultipleMiddleNames_ShouldIncludeInLastName()
    {
        var (firstName, lastName) = NameHelper.SplitName("John Michael Robert Smith");

        firstName.Should().Be("John");
        lastName.Should().Be("Michael Robert Smith");
    }
}
