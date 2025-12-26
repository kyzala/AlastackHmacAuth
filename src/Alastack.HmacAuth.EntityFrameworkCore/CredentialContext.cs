using Microsoft.EntityFrameworkCore;

namespace Alastack.HmacAuth.EntityFrameworkCore;

/// <summary>
/// A DbContext instance represents a session with the database and can be used to query and save
/// instances of your entities. DbContext is a combination of the Unit Of Work and Repository patterns.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
public class CredentialContext<TCredential> : DbContext where TCredential : class
{
    private readonly string _tableName;
    private readonly string _keyName;

    /// <summary>
    /// Initializes a new instance of <see cref="CredentialContext{TCredential}"/>.
    /// </summary>
    /// <param name="options">The options to be used by a <see cref="CredentialContext{TCredential}" />.</param>
    /// <param name="tableName">Credential table name.</param>
    /// <param name="keyName">Credential table key name.</param>
    public CredentialContext(DbContextOptions<CredentialContext<TCredential>> options, string tableName, string keyName)
        : base(options)
    {
        _tableName = tableName;
        _keyName = keyName;

        ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
    }

    /// <summary>
    /// The Sql implementation of <see cref="DbSet{TEntity}"/>.
    /// </summary>
    public DbSet<TCredential> Credentials { get; set; } = null!;

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        ConfigureCredentialContext(builder);
    }

    private void ConfigureCredentialContext(ModelBuilder builder)
    {
        builder.Entity<TCredential>().ToTable(_tableName);            
        builder.Entity<TCredential>(b =>
        {
            b.HasKey(_keyName);
        });
    }
}