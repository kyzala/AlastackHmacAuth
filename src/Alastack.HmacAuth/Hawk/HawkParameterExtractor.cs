namespace Alastack.HmacAuth;

/*
 * Hawk id="id123", ts="1660659477", nonce="A5GfwK", mac="KDUi6WaHtbpYxqxFWIeiZ2BhnBdV24pqaLf80dWL4mA="
 * Hawk id="id123", ts="1660659567", nonce="15jm4S", ext="somedata", mac="B56BbPIa5huwegSqLeckpASn9ATTrK4c9wDe4E/MFMc="
 * Hawk id="id123", ts="1660659612", nonce="VYrQae", ext="somedata", mac="6JScj2fCp5+T5xvMt9HDaOHGpJK38Bw1mfLB8UJ4KAU=", app="app123", dlg="dlg123"
 * Hawk id="id123", ts="1661697384", nonce="308052fd97ab4f4db6b590bed59a8860", ext="sp-data", mac="uVIUFwtrNueN8LJ/1vS4IDds9X8ilF87KW5uxYmruqo=", app="app", dlg="dlg"
 * Hawk id="authId123", ts="1659947138", nonce="nonce1233", hash="d6CWRMf5HisgSeLQ8uHWhDehAGa9ki71riGsGVw4FGQ=", ext="app-extra-data", mac="g48v1yb0duEUwUNLvS+Axz2eAMwidRPsExt+kogE01w=", app="appid", dlg="dlger"
 */

/// <summary>
/// The Hawk implementation of <see cref="IAuthorizationParameterExtractor"/>.
/// </summary>
public class HawkParameterExtractor : IAuthorizationParameterExtractor
{
    /// <inheritdoc />
    public IDictionary<string, string> Extract(string authorization)
    {
        var authVal = new Dictionary<string, string>();
        var authSpan = authorization.AsSpan();
        var index = authSpan.IndexOf(' ');
        authVal["scheme"] = authSpan[..index].ToString();
        authSpan = authSpan.Slice(index + 1).Trim();
        while (authSpan.Length > 4)
        {
            int start = authSpan.IndexOf("=\"");
            if (start < 1)
            {
                break;
            }
            int end = authSpan.IndexOf("\",");
            if (end == -1)
            {
                end = authSpan.Length - 1; // last
            }
            var name = authSpan[..start].ToString();
            authVal[name] = authSpan[(start + 2)..end].ToString();
            if (end == authSpan.Length - 1)
            {
                break;
            }
            authSpan = authSpan.Slice(end + 2).TrimStart();
        }
        return authVal;
    }
}