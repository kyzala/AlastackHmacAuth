namespace Alastack.HmacAuth;

/// <summary>
/// Represents the parsed Hawk authentication header parameters
/// </summary>
public class HawkParameters
{
    /// <summary>
    /// Gets or sets the authentication scheme
    /// </summary>
    public string Scheme { get; set; } = default!;

    /// <summary>
    /// Gets or sets the credentials identifier
    /// </summary>
    public string Id { get; set; } = default!;

    /// <summary>
    /// Gets or sets the timestamp
    /// </summary>
    public long Ts { get; set; }

    /// <summary>
    /// Gets or sets the nonce value
    /// </summary>
    public string Nonce { get; set; } = default!;

    /// <summary>
    /// Gets or sets the message authentication code
    /// </summary>
    public string Mac { get; set; } = default!;

    /// <summary>
    /// Gets or sets the payload hash
    /// </summary>
    public string? Hash { get; set; }

    /// <summary>
    /// Gets or sets the extension data
    /// </summary>
    public string? Ext { get; set; }

    /// <summary>
    /// Gets or sets the application ID
    /// </summary>
    public string? App { get; set; }

    /// <summary>
    /// Gets or sets the delegated-by identifier
    /// </summary>
    public string? Dlg { get; set; }

    /// <summary>
    /// Returns a string representation of the Hawk Authorization header
    /// </summary>
    /// <returns>A formatted Authorization header string</returns>
    /// <remarks>
    /// The returned string is in the format: "Scheme Parameter"
    /// Example: "Hawk id=\"123456\", ts=\"1353832234\", nonce=\"abc123\", mac=\"xyz789\""
    /// </remarks>
    public override string ToString()
    {
        return $"{Scheme} {Parameter}";
    }

    /// <summary>
    /// Gets the parameter portion of the Hawk Authorization header
    /// </summary>
    /// <value>
    /// A formatted string containing all Hawk parameters in the correct format.
    /// </value>
    /// <remarks>
    /// This property formats the parameters according to the Hawk 1.0 specification.
    /// Optional parameters are included only when they have values.
    /// </remarks>
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

    /// <summary>
    /// Parses a dictionary of authentication values into a <see cref="HawkParameters"/> instance
    /// </summary>
    /// <param name="authVal">A dictionary containing Hawk authentication parameters</param>
    /// <returns>A new <see cref="HawkParameters"/> instance populated with the parsed values</returns>
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