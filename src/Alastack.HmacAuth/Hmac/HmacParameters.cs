namespace Alastack.HmacAuth;

public class HmacParameters
{
    public string Scheme { get; set; } = default!;

    public string AppId { get; set; } = default!;

    public long Timestamp { get; set; }

    public string Nonce { get; set; } = default!;

    public string Signature { get; set; } = default!;

    public string PayloadHash { get; set; } = default!;

    public override string ToString()
    {
        return $"{Scheme} {Parameter}";
    }

    public string Parameter
    {
        get
        {
            return $"{AppId}:{Timestamp}:{Nonce}:{Signature}:{PayloadHash}";
        }
    }

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