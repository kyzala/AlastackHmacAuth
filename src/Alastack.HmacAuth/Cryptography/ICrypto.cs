namespace Alastack.HmacAuth;

/// <summary>
/// A hash algorithms abstraction.
/// </summary>
public interface ICrypto
{
    /// <summary>
    /// Computes the Hash-based Message Authentication Code (HMAC).
    /// </summary>
    /// <param name="buffer">The input to compute the hash code for.</param>
    /// <returns>The computed hash code.</returns>
    byte[] CalculateMac(byte[] buffer);

    /// <summary>
    /// Computes the Hash-based Message Authentication Code (HMAC).
    /// </summary>
    /// <param name="input">The input to compute the hash code for.</param>
    /// <returns>Base64 encoding of hash code.</returns>
    string CalculateMac(string input);

    /// <summary>
    /// Computes the hash value for the specified string.
    /// </summary>
    /// <param name="input">The input to compute the hash code for.</param>
    /// <returns>Base64 encoding of hash code.</returns>
    string CalculateHash(string input);

    /// <summary>
    /// Computes the hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">The input to compute the hash code for.</param>
    /// <returns>The computed hash code.</returns>
    byte[] CalculateHash(byte[] buffer);
}