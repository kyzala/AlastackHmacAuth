using Alastack.HmacAuth;

namespace Alastack.HmacAuth.Tests;

public class FixedTimeComparerTests
{
    [Fact]
    public void Equals_EqualStrings_ReturnsTrue()
    {
        Assert.True(FixedTimeComparer.Equals("abc123", "abc123"));
    }

    [Fact]
    public void Equals_EmptyStrings_ReturnsTrue()
    {
        Assert.True(FixedTimeComparer.Equals(string.Empty, string.Empty));
    }

    [Fact]
    public void Equals_DifferentStringsSameLength_ReturnsFalse()
    {
        Assert.False(FixedTimeComparer.Equals("abc123", "abc124"));
    }

    [Fact]
    public void Equals_DifferentLengths_ReturnsFalse()
    {
        Assert.False(FixedTimeComparer.Equals("abc", "abcdef"));
        Assert.False(FixedTimeComparer.Equals("abcdef", "abc"));
    }

    [Fact]
    public void Equals_BothNull_ReturnsTrue()
    {
        Assert.True(FixedTimeComparer.Equals(null, null));
    }

    [Theory]
    [InlineData(null, "abc")]
    [InlineData("abc", null)]
    public void Equals_OneNull_ReturnsFalse(string? left, string? right)
    {
        Assert.False(FixedTimeComparer.Equals(left, right));
    }

    [Fact]
    public void Equals_SameInstance_ReturnsTrue()
    {
        var value = "abc";
        Assert.True(FixedTimeComparer.Equals(value, value));
    }
}
