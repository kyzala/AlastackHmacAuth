using Alastack.HmacAuth.Credentials;
using LiteDB;

namespace Alastack.HmacAuth.LiteDB;

/// <summary>
/// The LiteDB implementation of <see cref="ICredentialProvider{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
public class LiteDBCredentialProvider<TCredential> : ICredentialProvider<TCredential>
{
    private LiteDatabase _database;
    private ILiteCollection<TCredential> _collection;
    private readonly BsonExpression _predicate;

    /// <summary>
    /// <see cref="LiteDBCredentialProviderSettings"/>.
    /// </summary>
    public LiteDBCredentialProviderSettings Settings { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="LiteDBCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="connectionString">Database connection string.</param>
    /// <param name="collectionName">Credential collection name.</param>
    /// <param name="keyName">Credential id field name.</param>
    public LiteDBCredentialProvider(string connectionString, string collectionName, string keyName)
        : this(new LiteDBCredentialProviderSettings { ConnectionString = connectionString, CollectionName = collectionName, KeyName = keyName })
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="LiteDBCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="settings"><see cref="LiteDBCredentialProviderSettings"/>.</param>
    public LiteDBCredentialProvider(LiteDBCredentialProviderSettings settings)
    {
        Settings = settings;
        _database = new LiteDatabase(Settings.ConnectionString);
        _collection = _database.GetCollection<TCredential>(Settings.CollectionName);
        _predicate = BsonExpression.Create($"{Settings.KeyName} = @0");
    }

    /// <inheritdoc />
    public virtual async Task<TCredential?> GetCredentialAsync(string id, CancellationToken token = default)
    {
        //var database = new LiteDatabase(Settings.ConnectionString);
        //var collection = database.GetCollection<TCredential>(Settings.CollectionName);
        var credential = _collection.FindOne(_predicate, id);
        return await Task.FromResult(credential);
    }

    /// <summary>
    /// Init LiteDB database.
    /// </summary>
    /// <param name="enforce">Whether to delete the existing database file.</param>
    public void InitDatabase(bool enforce = false)
    {
        if (enforce)
        {
            _database.Dispose();
            var dbfile = Settings.ConnectionString.Split(';')
                .First(str => str.StartsWith("Filename=", StringComparison.OrdinalIgnoreCase))
                .Substring(9);
            if (File.Exists(dbfile)) 
            {
                File.Delete(dbfile);
            }                
            var dblogfile = Path.GetFileNameWithoutExtension(dbfile) + "-log" + Path.GetExtension(dbfile);
            if (File.Exists(dblogfile))
            {
                File.Delete(dblogfile);
            }
            _database = new LiteDatabase(Settings.ConnectionString);
            _collection = _database.GetCollection<TCredential>(Settings.CollectionName);
        }
        //using var database = new LiteDatabase(Settings.ConnectionString);
        //var collection = database.GetCollection<TCredential>(Settings.CollectionName);
        if (_collection.Count() == 0)
        {
            var expression = BsonExpression.Create($"{Settings.CollectionName}.{Settings.KeyName}");
            _collection.EnsureIndex($"Idx_{Settings.CollectionName}_{Settings.KeyName}", expression, true);
        }
    }

    /// <summary>
    /// Add new credential.
    /// </summary>
    /// <param name="credential">Credential object.</param>
    public void AddCredential(TCredential credential)
    {
        _collection.Insert(credential);
    }
}