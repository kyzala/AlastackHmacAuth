using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth;

/// <summary>
/// Class used to validate <see cref="HawkSettings" /> instance.
/// </summary>
public class HawkSettingsValidation : IValidateOptions<HawkSettings>
{
    /// <summary>
    /// Validates a specific named options instance (or all when name is null).
    /// </summary>
    /// <param name="name">The name of the options instance being validated.</param>
    /// <param name="options">The options instance.</param>
    /// <returns>The <see cref="ValidateOptionsResult" /> result.</returns>
    public ValidateOptionsResult Validate(string? name, HawkSettings options)
    {
        string? vor = null;
        if (String.IsNullOrWhiteSpace(options.AuthId))
        {
            vor = $"{nameof(options.AuthId)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.AuthKey))
        {
            vor += $"{nameof(options.AuthKey)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.HmacAlgorithm))
        {
            vor += $"{nameof(options.HmacAlgorithm)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.HmacAlgorithm))
        {
            vor += $"{nameof(options.HmacAlgorithm)} must not be null or whitespace.";
        }

        if (vor != null)
        {
            return ValidateOptionsResult.Fail(vor);
        }

        return ValidateOptionsResult.Success;
    }
}