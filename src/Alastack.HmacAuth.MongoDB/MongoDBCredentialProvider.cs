using Alastack.HmacAuth.Credentials;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Driver;
using System.Threading;

namespace Alastack.HmacAuth.MongoDB;

/// <summary>
/// The MongoDB implementation of <see cref="ICredentialProvider{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
public class MongoDBCredentialProvider<TCredential> : ICredentialProvider<TCredential>
{
    private readonly IMongoDatabase _database;

    /// <summary>
    /// <see cref="MongoDBCredentialProviderSettings"/>.
    /// </summary>
    public MongoDBCredentialProviderSettings Settings { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="MongoDBCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="connectionString">Database connection string.</param>
    /// <param name="databaseName">Database name.</param>
    /// <param name="collectionName">Credential collection name.</param>
    /// <param name="keyName">Credential id field name.</param>
    public MongoDBCredentialProvider(string connectionString, string databaseName, string collectionName, string keyName)
        : this(new MongoDBCredentialProviderSettings { ConnectionString = connectionString, DatabaseName = databaseName, CollectionName = collectionName, KeyName = keyName })
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="MongoDBCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="settings"><see cref="MongoDBCredentialProviderSettings"/>.</param>
    public MongoDBCredentialProvider(MongoDBCredentialProviderSettings settings)
    {
        Settings = settings;
        var client = new MongoClient(Settings.ConnectionString);
        _database = client.GetDatabase(Settings.DatabaseName);

        var pack = new ConventionPack
        {
            new CamelCaseElementNameConvention(),
            new IgnoreExtraElementsConvention(true)
        };
        ConventionRegistry.Register("customConvention", pack, type => true);
    }

    /// <inheritdoc />
    public virtual async Task<TCredential?> GetCredentialAsync(string id, CancellationToken token = default)
    {
        TCredential? credential = default;
        var collection = _database.GetCollection<BsonDocument>(Settings.CollectionName);
        var documents = await collection.FindAsync(new BsonDocument(Settings.KeyName, id), cancellationToken: token);
        var document = await documents.SingleOrDefaultAsync(token);
        if (document != null)
        {
            credential = BsonSerializer.Deserialize<TCredential>(document);
        }
        return credential;
    }
}