using System.Security.Cryptography;
using System.Text;

namespace Alastack.HmacAuth;

/// <summary>
/// Provides a constant-time string equality operation to mitigate timing attacks when comparing signatures or MACs.
/// </summary>
public static class FixedTimeComparer
{
    /// <summary>
    /// Determines whether two strings are equal without leaking timing information about the content.
    /// </summary>
    /// <param name="left">The first string to compare.</param>
    /// <param name="right">The second string to compare.</param>
    /// <returns><c>true</c> if both strings are equal; otherwise, <c>false</c>.</returns>
    public static bool Equals(string? left, string? right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }
        if (left is null || right is null)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
    }
}
