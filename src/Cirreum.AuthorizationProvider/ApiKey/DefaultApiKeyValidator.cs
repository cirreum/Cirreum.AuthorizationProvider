namespace Cirreum.AuthorizationProvider.ApiKey;

using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

/// <summary>
/// Default implementation of <see cref="IApiKeyValidator"/> providing secure
/// validation utilities for API keys.
/// </summary>
public sealed class DefaultApiKeyValidator : IApiKeyValidator {

	private readonly ApiKeyValidationOptions _options;

	/// <summary>
	/// Initializes a new instance of the <see cref="DefaultApiKeyValidator"/> class.
	/// </summary>
	/// <param name="options">The validation options.</param>
	public DefaultApiKeyValidator(IOptions<ApiKeyValidationOptions> options) {
		_options = options?.Value ?? new ApiKeyValidationOptions();
	}

	/// <summary>
	/// Initializes a new instance with default options.
	/// </summary>
	public DefaultApiKeyValidator() : this(Options.Create(new ApiKeyValidationOptions())) { }

	/// <inheritdoc/>
	public ApiKeyFormatValidationResult ValidateFormat(string key) {
		if (string.IsNullOrWhiteSpace(key)) {
			return ApiKeyFormatValidationResult.Invalid("API key cannot be empty");
		}

		if (key.Length < _options.MinimumKeyLength) {
			return ApiKeyFormatValidationResult.Invalid(
				$"API key must be at least {_options.MinimumKeyLength} characters");
		}

		if (key.Length > _options.MaximumKeyLength) {
			return ApiKeyFormatValidationResult.Invalid(
				$"API key cannot exceed {_options.MaximumKeyLength} characters");
		}

		if (_options.EnforceValidCharacters) {
			var validChars = _options.ValidCharacters.ToHashSet();
			foreach (var c in key) {
				if (!validChars.Contains(c)) {
					return ApiKeyFormatValidationResult.Invalid(
						$"API key contains invalid character: '{c}'");
				}
			}
		}

		return ApiKeyFormatValidationResult.Valid();
	}

	/// <inheritdoc/>
	public bool CompareKeysSecurely(string providedKey, string expectedKey) {
		if (string.IsNullOrEmpty(providedKey) || string.IsNullOrEmpty(expectedKey)) {
			return false;
		}

		var providedBytes = Encoding.UTF8.GetBytes(providedKey);
		var expectedBytes = Encoding.UTF8.GetBytes(expectedKey);

		return CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes);
	}

	/// <inheritdoc/>
	public bool ValidateKeyHash(string providedKey, string storedHash, string? salt = null) {
		if (string.IsNullOrEmpty(providedKey) || string.IsNullOrEmpty(storedHash)) {
			return false;
		}

		var computedHash = HashKey(providedKey, salt);
		return CompareKeysSecurely(computedHash.Hash, storedHash);
	}

	/// <inheritdoc/>
	public bool IsExpired(DateTimeOffset? expiresAt, TimeSpan? gracePeriod = null) {
		if (_options.AllowExpiredKeys) {
			return false;
		}

		if (expiresAt is null) {
			return false;
		}

		var effectiveGracePeriod = gracePeriod ?? _options.ExpirationGracePeriod;
		var effectiveExpiration = expiresAt.Value.Add(effectiveGracePeriod);

		return DateTimeOffset.UtcNow > effectiveExpiration;
	}

	/// <inheritdoc/>
	public ApiKeyHashResult HashKey(string key, string? salt = null) {
		ArgumentException.ThrowIfNullOrWhiteSpace(key);

		// Generate salt if not provided
		salt ??= GenerateSalt();

		// Combine key and salt
		var combined = $"{salt}{key}";
		var bytes = Encoding.UTF8.GetBytes(combined);

		// Use SHA256 for hashing
		var hashBytes = SHA256.HashData(bytes);
		var hash = Convert.ToBase64String(hashBytes);

		return new ApiKeyHashResult(hash, salt);
	}

	/// <summary>
	/// Generates a cryptographically secure random salt.
	/// </summary>
	private static string GenerateSalt() {
		var saltBytes = new byte[32];
		RandomNumberGenerator.Fill(saltBytes);
		return Convert.ToBase64String(saltBytes);
	}
}
