namespace Alastack.HmacAuth.MongoDB;

/// <summary>
/// MongoDB CredentialProvider settings.
/// </summary>
public class MongoDBCredentialProviderSettings
{
    /// <summary>
    /// Credential database connection string.
    /// </summary>
    public string ConnectionString { get; set; } = default!;

    /// <summary>
    /// Credential database name.
    /// </summary>
    public string DatabaseName { get; set; } = default!;

    /// <summary>
    /// Credential collection name.
    /// </summary>
    public string CollectionName { get; set; } = default!;

    /// <summary>
    /// Credential id field name.
    /// </summary>
    public string KeyName { get; set; } = default!;
}
