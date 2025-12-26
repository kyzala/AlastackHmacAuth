namespace Alastack.HmacAuth.EntityFrameworkCore;

/// <summary>
/// EFCore CredentialProvider settings.
/// </summary>
public class EFCoreCredentialProviderSettings
{
    /// <summary>
    /// Credential table name.
    /// </summary>
    public string TableName { get; set; } = default!;

    /// <summary>
    /// Credential table key name.
    /// </summary>
    public string KeyName { get; set; } = default!;
}
