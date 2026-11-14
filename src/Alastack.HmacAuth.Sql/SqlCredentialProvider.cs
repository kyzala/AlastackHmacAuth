using Alastack.HmacAuth.Credentials;
using System.Collections.Concurrent;
using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Reflection;

namespace Alastack.HmacAuth.Sql;

/// <summary>
/// The Sql implementation of <see cref="ICredentialProvider{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
/// <typeparam name="TConnection">A connection type.</typeparam>
public class SqlCredentialProvider<TCredential, TConnection> : ICredentialProvider<TCredential> where TConnection : IDbConnection, new()
{
    private static readonly ConcurrentDictionary<Type, Dictionary<string, PropertyInfo>> PropertyMaps = new();

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
    public virtual async Task<TCredential?> GetCredentialAsync(string id, CancellationToken cancellationToken = default)
    {
        using var connection = new TConnection { ConnectionString = Settings.ConnectionString };
        await OpenAsync(connection, cancellationToken).ConfigureAwait(false);

        using var command = connection.CreateCommand();
        command.CommandText = Settings.Sql;
        var parameter = command.CreateParameter();
        parameter.ParameterName = "Id";
        parameter.DbType = DbType.String;
        parameter.Value = id;
        command.Parameters.Add(parameter);

        if (command is DbCommand dbCommand)
        {
            using var reader = await dbCommand.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
            return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? Map(reader) : default;
        }
        else
        {
            using var reader = command.ExecuteReader(CommandBehavior.SingleRow);
            return reader.Read() ? Map(reader) : default;
        }
    }

    private static async Task OpenAsync(IDbConnection connection, CancellationToken cancellationToken)
    {
        if (connection.State == ConnectionState.Open)
        {
            return;
        }
        if (connection is DbConnection dbConnection)
        {
            await dbConnection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            connection.Open();
        }
    }

    private static TCredential Map(IDataRecord record)
    {
        var propertyMap = PropertyMaps.GetOrAdd(typeof(TCredential), CreatePropertyMap);
        var credential = Activator.CreateInstance<TCredential>()!;
        for (var i = 0; i < record.FieldCount; i++)
        {
            if (!propertyMap.TryGetValue(record.GetName(i), out var property))
            {
                continue;
            }
            var value = record.GetValue(i);
            if (value is DBNull)
            {
                continue;
            }
            property.SetValue(credential, ConvertValue(value, property.PropertyType));
        }
        return credential;
    }

    private static Dictionary<string, PropertyInfo> CreatePropertyMap(Type type)
    {
        var map = new Dictionary<string, PropertyInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.CanWrite && property.GetIndexParameters().Length == 0)
            {
                map[property.Name] = property;
            }
        }
        return map;
    }

    private static object ConvertValue(object value, Type propertyType)
    {
        var targetType = Nullable.GetUnderlyingType(propertyType) ?? propertyType;
        if (targetType.IsInstanceOfType(value))
        {
            return value;
        }
        if (targetType == typeof(string))
        {
            return value.ToString()!;
        }
        if (targetType.IsEnum)
        {
            return Enum.ToObject(targetType, value);
        }
        return Convert.ChangeType(value, targetType, CultureInfo.InvariantCulture);
    }
}
