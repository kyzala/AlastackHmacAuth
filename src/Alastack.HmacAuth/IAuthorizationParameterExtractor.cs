namespace Alastack.HmacAuth;

/// <summary>
/// a HTTP Authorization header parameter extractor abstraction.
/// </summary>
public interface IAuthorizationParameterExtractor
{
    /// <summary>
    /// Extract authorization parameter.
    /// </summary>
    /// <param name="authorization">Authorization header value.</param>
    /// <returns>authorization parameter dictionary.</returns>
    IDictionary<string, string> Extract(string authorization);
}