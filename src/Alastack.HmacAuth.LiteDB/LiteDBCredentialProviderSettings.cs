namespace Alastack.HmacAuth.LiteDB;

/// <summary>
/// LiteDB CredentialProvider settings.
/// </summary>
public class LiteDBCredentialProviderSettings
{
    /// <summary>
    /// Credential database connection string.
    /// </summary>
    public string ConnectionString { get; set; } = default!;
            
    /// <summary>
    /// Credential collection name.
    /// </summary>
    public string CollectionName { get; set; } = default!;

    /// <summary>
    /// Credential id field name.
    /// </summary>
    public string KeyName { get; set; } = default!;
}
