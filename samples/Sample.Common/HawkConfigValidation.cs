using Alastack.HmacAuth;
using Microsoft.Extensions.Options;

namespace Sample.Common;

/// <summary>
/// Class used to validate <see cref="HawkSettings" /> instance.
/// </summary>
public class HawkConfigValidation : IValidateOptions<HawkSettings>
{
    /// <summary>
    /// Validates a specific named options instance (or all when name is null).
    /// </summary>
    /// <param name="name">The name of the options instance being validated.</param>
    /// <param name="options">The options instance.</param>
    /// <returns>The <see cref="ValidateOptionsResult" /> result.</returns>
    public ValidateOptionsResult Validate(string? name, HawkSettings options)
    {
        var result = new HawkConfigValidator().Validate(options);
        if (result.Succeeded)
        {
            return ValidateOptionsResult.Success;
            
        }
        return ValidateOptionsResult.Fail(result.FailureMessage!);
    }
}