using Alastack.HmacAuth.Credentials;
using Microsoft.EntityFrameworkCore;

namespace Alastack.HmacAuth.EFCore;

/// <summary>
/// The MongoDB implementation of <see cref="ICredentialProvider{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
public class EFCoreCredentialProvider<TCredential> : ICredentialProvider<TCredential> where TCredential : class
{
    /// <summary>
    /// <see cref="EFCoreCredentialProviderSettings"/>.
    /// </summary>
    private EFCoreCredentialProviderSettings Settings { get; }

    private readonly DbContextOptions<CredentialContext<TCredential>> _contextOptions;

    /// <summary>
    /// Initializes a new instance of <see cref="EFCoreCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="optionsBuilder">Provides a simple API surface for configuring <see cref="DbContextOptions{TContext}" />.</param>
    /// <param name="tableName">Credential table name.</param>
    /// <param name="keyName">Credential table key name.</param>
    public EFCoreCredentialProvider(DbContextOptionsBuilder<CredentialContext<TCredential>> optionsBuilder, string tableName, string keyName)
        : this(optionsBuilder.Options, tableName, keyName)
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="EFCoreCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="optionsBuilder">Provides a simple API surface for configuring <see cref="DbContextOptions{TContext}" />.</param>
    /// <param name="settings"><see cref="EFCoreCredentialProviderSettings"/>.</param>
    public EFCoreCredentialProvider(DbContextOptionsBuilder<CredentialContext<TCredential>> optionsBuilder, EFCoreCredentialProviderSettings settings)
        : this(optionsBuilder.Options, settings)
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="EFCoreCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="contextOptions">The options to be used by a <see cref="CredentialContext{TCredential}" />.</param>
    /// <param name="tableName">Credential table name.</param>
    /// <param name="keyName">Credential table key name.</param>
    public EFCoreCredentialProvider(DbContextOptions<CredentialContext<TCredential>> contextOptions, string tableName, string keyName)
        : this(contextOptions, new EFCoreCredentialProviderSettings { TableName = tableName, KeyName = keyName })
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="EFCoreCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="contextOptions">The options to be used by a <see cref="CredentialContext{TCredential}" />.</param>
    /// <param name="settings"><see cref="EFCoreCredentialProviderSettings"/>.</param>
    public EFCoreCredentialProvider(DbContextOptions<CredentialContext<TCredential>> contextOptions, EFCoreCredentialProviderSettings settings)
    {
        _contextOptions = contextOptions;
        Settings = settings;
    }

    /// <inheritdoc />
    public virtual async Task<TCredential?> GetCredentialAsync(string id, CancellationToken token = default)
    {
        using var context = new CredentialContext<TCredential>(_contextOptions, Settings.TableName, Settings.KeyName);
        return await context.Credentials.FindAsync(id, token);
    }
}