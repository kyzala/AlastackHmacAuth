using Alastack.HmacAuth.Credentials;
using Dapper;
using System.Data;
using static Dapper.SqlMapper;

namespace Alastack.HmacAuth.Sql;

/// <summary>
/// The Sql implementation of <see cref="ICredentialProvider{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
/// <typeparam name="TConnection">A connection type.</typeparam>
public class SqlCredentialProvider<TCredential, TConnection> : ICredentialProvider<TCredential> where TConnection : IDbConnection, new()
{
    /// <summary>
    /// <see cref="SqlCredentialProviderSettings"/>.
    /// </summary>
    public SqlCredentialProviderSettings Settings { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="SqlCredentialProvider{TCredential, TConnection}"/>.
    /// </summary>
    /// <param name="connectionString">Database connection string.</param>
    /// <param name="sql">Credential query sql.</param>
    public SqlCredentialProvider(string connectionString, string sql)
        : this(new SqlCredentialProviderSettings { ConnectionString = connectionString, Sql = sql })
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="SqlCredentialProvider{TCredential, TConnection}"/>.
    /// </summary>
    /// <param name="settings"><see cref="SqlCredentialProviderSettings"/>.</param>
    public SqlCredentialProvider(SqlCredentialProviderSettings settings)
    {
        Settings = settings;
    }

    /// <inheritdoc />
    public virtual async Task<TCredential?> GetCredentialAsync(string id, CancellationToken token = default)
    {
        using var connection = new TConnection { ConnectionString = Settings.ConnectionString };
        return await connection.QueryFirstOrDefaultAsync<TCredential>(Settings.Sql, new { Id = id });
    }
}