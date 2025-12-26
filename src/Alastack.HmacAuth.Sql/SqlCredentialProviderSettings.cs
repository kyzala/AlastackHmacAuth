namespace Alastack.HmacAuth.Sql;

/// <summary>
/// Sql CredentialProvider settings.
/// </summary>
public class SqlCredentialProviderSettings
{
    /// <summary>
    /// Database connection string.
    /// </summary>
    public string ConnectionString { get; set; } = default!;

    /// <summary>
    /// Credential query sql.
    /// </summary>
    public string Sql { get; set; } = default!;

    //public string SqlType { get; set; }
}