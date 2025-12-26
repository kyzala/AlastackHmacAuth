namespace Alastack.HmacAuth;

/// <summary>
/// A nonce generator abstraction.
/// </summary>
public interface INonceGenerator
{
    /// <summary>
    /// Generate nonce string.
    /// </summary>
    /// <param name="id">HTTP reqeust id.</param>
    /// <returns>A nonce string.</returns>
    string Generate(string id);
}