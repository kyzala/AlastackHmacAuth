namespace Alastack.HmacAuth;

/// <summary>
/// Contains data required for Hawk authentication calculations
/// </summary>
public class HawkData
{
    /// <summary>
    /// Unix timestamp in seconds
    /// </summary>
    public long Timestamp { get; set; }

    /// <summary>
    /// Unique request identifier
    /// </summary>
    public string Nonce { get; set; } = default!;

    /// <summary>
    /// HTTP method (GET, POST, etc.)
    /// </summary>
    public string Method { get; set; } = default!;

    /// <summary>
    /// Request URI path and query
    /// </summary>
    public string Resource { get; set; } = default!;

    /// <summary>
    /// Server hostname
    /// </summary>
    public string Host { get; set; } = default!;

    /// <summary>
    /// Server port number
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// Optional payload hash
    /// </summary>
    public string? Hash { get; set; }

    /// <summary>
    /// Optional extension data
    /// </summary>
    public string? Ext { get; set; }

    /// <summary>
    /// Optional application ID for delegation
    /// </summary>
    public string? App { get; set; }

    /// <summary>
    /// Optional delegator identifier
    /// </summary>
    public string? Dlg { get; set; }
}