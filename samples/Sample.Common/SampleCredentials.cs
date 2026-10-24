namespace Sample.Common;

/// <summary>
/// Credential and endpoint constants shared by all samples. They must match the
/// credentials configured by the sample hosts (see ApiHostSample).
/// </summary>
public static class SampleCredentials
{
    public const string AppId = "id123";
    public const string AppKey = "3@uo45er?";

    public const string HawkApp = "app1234";
    public const string HawkDlg = "dlg1234";
    public const string HawkSpecificData = "some-data";

    /// <summary>ApiHostSample default address.</summary>
    public const string DefaultBaseAddress = "https://localhost:5001/";
}
