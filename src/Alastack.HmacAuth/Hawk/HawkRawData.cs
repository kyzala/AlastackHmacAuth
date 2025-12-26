namespace Alastack.HmacAuth;

public class HawkRawData
{
    public long Timestamp { get; set; }
    public string Nonce { get; set; } = default!;
    public string Method { get; set; } = default!;
    public string Resource { get; set; } = default!;
    public string Host { get; set; } = default!;
    public int Port { get; set; }
    public string? Hash { get; set; }
    public string? Ext { get; set; }
    public string? App { get; set; }
    public string? Dlg { get; set; }
}