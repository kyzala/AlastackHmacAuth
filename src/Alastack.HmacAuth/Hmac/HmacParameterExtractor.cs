namespace Alastack.HmacAuth;

/*
 * Hmac {appId}:{timestamp}:{nonce}:{signature}:{payloadHash}
 */

/// <summary>
/// The Hmac implementation of <see cref="IAuthorizationParameterExtractor"/>.
/// </summary>
public class HmacParameterExtractor : IAuthorizationParameterExtractor
{
    /// <inheritdoc />
    public IDictionary<string, string> Extract(string authorization)
    {
        var authVal = new Dictionary<string, string>();
        var array = authorization.Split(new[] { ':', ' ' }, StringSplitOptions.None);
        if (array.Length == 6)
        {
            authVal["scheme"] = array[0];
            authVal["appId"] = array[1];
            authVal["timestamp"] = array[2];
            authVal["nonce"] = array[3];
            authVal["signature"] = array[4];
            authVal["payloadHash"] = array[5];
        }
        return authVal;
    }
}