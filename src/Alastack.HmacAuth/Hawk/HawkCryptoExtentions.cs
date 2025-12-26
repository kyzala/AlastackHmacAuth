using System.Text;

namespace Alastack.HmacAuth;

public static class HawkCryptoExtentions
{
    public static string CalculateRequestMac(this ICrypto crypto, HawkRawData parameters)
    {
        return crypto.CalculateMac("header", parameters);
    }

    public static string CalculateResponseMac(this ICrypto crypto, HawkRawData parameters)
    {
        return crypto.CalculateMac("response", parameters);
    }
    public static string CalculateMac(this ICrypto crypto, string type, HawkRawData parameters)
    {
        var normalizedString = $"hawk.1.{type}\n{parameters.Timestamp}\n{parameters.Nonce}\n{parameters.Method}\n{parameters.Resource}\n{parameters.Host}\n{parameters.Port}\n";
        normalizedString += $"{parameters.Hash ?? String.Empty}\n";
        normalizedString += $"{parameters.Ext ?? String.Empty}\n";
        if (parameters.App != null)
        {
            normalizedString += $"{parameters.App}\n{parameters.Dlg ?? String.Empty}\n";
        }
        return crypto.CalculateMac(normalizedString);
    }

    public static string CalculateTsMac(this ICrypto crypto, long timestamp)
    {
        var normalizedString = $"hawk.1.ts\n{timestamp}\n";
        return crypto.CalculateMac(normalizedString);
    }

    public static string CalculatePayloadHash(this ICrypto crypto, string? payload, string? contentType)
    {
        var normalizedString = $"hawk.1.payload\n{contentType?.ToLower() ?? String.Empty}\n{payload ?? String.Empty}\n";
        var hash = crypto.CalculateHash(Encoding.UTF8.GetBytes(normalizedString));
        return Convert.ToBase64String(hash);
    }

    public static string CalculatePayloadHash(this ICrypto crypto, byte[] payloadBytes, string? contentType)
    {
        string payload = Encoding.UTF8.GetString(payloadBytes);
        return CalculatePayloadHash(crypto, payload, contentType);
    }

    //public static string CalculateHawkPayloadHash(this ICrypto crypto, Stream payloadStream, string contentType) 
    //{

    //}
}