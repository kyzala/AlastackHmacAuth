namespace Alastack.HmacAuth;

public class HawkParameters
{
    public string Scheme { get; set; } = default!;
    public string Id { get; set; } = default!;
    public long Ts { get; set; }
    public string Nonce { get; set; } = default!;
    public string Mac { get; set; } = default!;
    public string? Hash { get; set; }
    public string? Ext { get; set; }
    public string? App { get; set; }
    public string? Dlg { get; set; }

    //private static readonly string[] _parameterNames = new string[] { "id", "ts", "nonce", "hash", "ext", "app", "dlg" };

    public override string ToString()
    {
        return $"{Scheme} {Parameter}";
    }

    public string Parameter
    {
        get
        {
            var hash = string.IsNullOrWhiteSpace(Hash) ? String.Empty : $"hash=\"{Hash}\", ";
            var ext = string.IsNullOrWhiteSpace(Ext) ? String.Empty : $"ext=\"{Ext}\", ";
            var appdlg = string.IsNullOrWhiteSpace(App) ? String.Empty : $", app=\"{App}\", dlg=\"{Dlg ?? String.Empty}\"";
            return $"id=\"{Id}\", ts=\"{Ts}\", nonce=\"{Nonce}\", {hash}{ext}mac=\"{Mac}\"{appdlg}";
        }
    }

    public static HawkParameters Parse(IDictionary<string, string> authVal)
    {
        return new()
        {
            Scheme = authVal["scheme"],
            Id = authVal["id"],
            Ts = long.Parse(authVal["ts"]),
            Nonce = authVal["nonce"],
            Mac = authVal["mac"],
            Ext = authVal.ContainsKey("ext") ? authVal["ext"] : null,
            Hash = authVal.ContainsKey("hash") ? authVal["hash"] : null,
            App = authVal.ContainsKey("app") ? authVal["app"] : null,
            Dlg = authVal.ContainsKey("dlg") ? authVal["dlg"] : null
        };
    }
}