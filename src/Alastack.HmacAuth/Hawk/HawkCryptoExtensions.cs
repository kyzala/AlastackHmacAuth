using System.Text;

namespace Alastack.HmacAuth;

/// <summary>
/// Provides extension methods for Hawk authentication protocol cryptographic operations
/// </summary>
public static class HawkCryptoExtensions
{
    /// <summary>
    /// Calculates the MAC (Message Authentication Code) for a Hawk request header
    /// </summary>
    /// <param name="crypto">The cryptographic instance</param>
    /// <param name="hawkData">The Hawk authentication data</param>
    /// <returns>A Base64-encoded MAC string for the request header</returns>
    public static string CalculateRequestMac(this ICrypto crypto, HawkData hawkData)
    {
        return crypto.CalculateMac("header", hawkData);
    }

    /// <summary>
    /// Calculates the MAC (Message Authentication Code) for a Hawk response
    /// </summary>
    /// <param name="crypto">The cryptographic instance</param>
    /// <param name="hawkData">The Hawk authentication data</param>
    /// <returns>A Base64-encoded MAC string for the response</returns>
    public static string CalculateResponseMac(this ICrypto crypto, HawkData hawkData)
    {
        return crypto.CalculateMac("response", hawkData);
    }

    /// <summary>
    /// Calculates a MAC for a specified Hawk message type
    /// </summary>
    /// <param name="crypto">The cryptographic instance</param>
    /// <param name="type">The Hawk message type ("header" or "response")</param>
    /// <param name="hawkData">The Hawk authentication data</param>
    /// <returns>A Base64-encoded MAC string</returns>
    public static string CalculateMac(this ICrypto crypto, string type, HawkData hawkData)
    {
        var normalizedString = $"hawk.1.{type}\n{hawkData.Timestamp}\n{hawkData.Nonce}\n{hawkData.Method}\n{hawkData.Resource}\n{hawkData.Host}\n{hawkData.Port}\n{hawkData.Hash ?? String.Empty}\n{hawkData.Ext ?? String.Empty}\n";
        //normalizedString += $"{hawkData.Hash ?? String.Empty}\n";
        //normalizedString += $"{hawkData.Ext ?? String.Empty}\n";
        if (hawkData.App != null)
        {
            normalizedString += $"{hawkData.App}\n{hawkData.Dlg ?? String.Empty}\n";
        }
        return crypto.CalculateMac(normalizedString);
    }

    /// <summary>
    /// Calculates a timestamp MAC for timestamp validation
    /// </summary>
    /// <param name="crypto">The cryptographic instance</param>
    /// <param name="timestamp">Unix timestamp in seconds</param>
    /// <returns>A Base64-encoded timestamp MAC</returns>
    public static string CalculateTsMac(this ICrypto crypto, long timestamp)
    {
        var normalizedString = $"hawk.1.ts\n{timestamp}\n";
        return crypto.CalculateMac(normalizedString);
    }

    /// <summary>
    /// Calculates the payload hash for request/response bodies
    /// </summary>
    /// <param name="crypto">The cryptographic instance</param>
    /// <param name="payload">The request/response payload as a string (may be null for empty payload)</param>
    /// <param name="contentType">The Content-Type header value (may be null)</param>
    /// <returns>A Base64-encoded payload hash</returns>
    public static string CalculatePayloadHash(this ICrypto crypto, string? payload, string? contentType)
    {
        var normalizedString = $"hawk.1.payload\n{contentType?.ToLower() ?? String.Empty}\n{payload ?? String.Empty}\n";
        var hash = crypto.CalculateHash(Encoding.UTF8.GetBytes(normalizedString));
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Calculates the payload hash for request/response bodies from byte array
    /// </summary>
    /// <param name="crypto">The cryptographic instance</param>
    /// <param name="payloadBytes">The request/response payload as a byte array</param>
    /// <param name="contentType">The Content-Type header value (may be null)</param>
    /// <returns>A Base64-encoded payload hash</returns>
    public static string CalculatePayloadHash(this ICrypto crypto, byte[] payloadBytes, string? contentType)
    {
        string payload = Encoding.UTF8.GetString(payloadBytes);
        return CalculatePayloadHash(crypto, payload, contentType);
    }

    //public static string CalculateHawkPayloadHash(this ICrypto crypto, Stream payloadStream, string contentType) 
    //{

    //}
}