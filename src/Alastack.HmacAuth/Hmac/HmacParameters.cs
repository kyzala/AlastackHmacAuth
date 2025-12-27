namespace Alastack.HmacAuth;

/// <summary>
/// Represents the parsed HMAC-based authentication header parameters
/// </summary>
public class HmacParameters
{
    /// <summary>
    /// Gets or sets the authentication scheme
    /// </summary>
    public string Scheme { get; set; } = default!;

    /// <summary>
    /// Gets or sets the application identifier
    /// </summary>
    public string AppId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the timestamp
    /// </summary>
    public long Timestamp { get; set; }

    /// <summary>
    /// Gets or sets the nonce value
    /// </summary>
    public string Nonce { get; set; } = default!;

    /// <summary>
    /// Gets or sets the request signature
    /// </summary>
    public string Signature { get; set; } = default!;

    /// <summary>
    /// Gets or sets the payload hash
    /// </summary>
    public string PayloadHash { get; set; } = default!;

    /// <summary>
    /// Returns a string representation of the HMAC Authorization header
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
        return $"{Scheme} {Parameter}";
    }

    /// <summary>
    /// Gets the parameter portion of the HMAC Authorization header
    /// </summary>
    public string Parameter
    {
        get
        {
            return $"{AppId}:{Timestamp}:{Nonce}:{Signature}:{PayloadHash}";
        }
    }

    /// <summary>
    /// Parses a dictionary of authentication values into an <see cref="HmacParameters"/> instance
    /// </summary>
    /// <param name="authVal">A dictionary containing HMAC authentication parameters</param>
    /// <returns>A new <see cref="HmacParameters"/> instance populated with the parsed values</returns>
    public static HmacParameters Parse(IDictionary<string, string> authVal)
    {
        return new()
        {
            Scheme = authVal["scheme"],
            AppId = authVal["appId"],
            Timestamp = long.Parse(authVal["timestamp"]),
            Nonce = authVal["nonce"],
            Signature = authVal["signature"],
            PayloadHash = authVal["payloadHash"]
        };
    }
}