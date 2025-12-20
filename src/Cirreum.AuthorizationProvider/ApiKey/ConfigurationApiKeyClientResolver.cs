namespace Cirreum.AuthorizationProvider.ApiKey;

using Microsoft.Extensions.Logging;

/// <summary>
/// Resolves API key clients from the configuration-based <see cref="ApiKeyClientRegistry"/>.
/// This is the default resolver that maintains backward compatibility with existing
/// appsettings/KeyVault-based key storage.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="ConfigurationApiKeyClientResolver"/> class.
/// </remarks>
/// <param name="registry">The API key client registry.</param>
/// <param name="validator">The API key validator.</param>
/// <param name="logger">The logger.</param>
public sealed class ConfigurationApiKeyClientResolver(
	ApiKeyClientRegistry registry,
	IApiKeyValidator validator,
	ILogger<ConfigurationApiKeyClientResolver> logger
) : IApiKeyClientResolver {

	private readonly ApiKeyClientRegistry _registry = registry ?? throw new ArgumentNullException(nameof(registry));
	private readonly IApiKeyValidator _validator = validator ?? throw new ArgumentNullException(nameof(validator));
	private readonly ILogger<ConfigurationApiKeyClientResolver> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

	/// <inheritdoc/>
	public IReadOnlySet<string> SupportedHeaders => _registry.RegisteredHeaders;

	/// <inheritdoc/>
	public Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		var headerName = context.HeaderName;

		// Validate format first
		var formatResult = _validator.ValidateFormat(providedKey);
		if (!formatResult.IsValid) {
			if (_logger.IsEnabled(LogLevel.Debug)) {
				_logger.LogDebug(
					"API key format validation failed for header {HeaderName}: {Reason}",
					headerName,
					formatResult.ErrorReason);
			}
			return Task.FromResult(ApiKeyResolveResult.Failed(formatResult.ErrorReason!));
		}

		// Look up in registry (uses constant-time comparison internally)
		var entry = _registry.ValidateKey(headerName, providedKey);

		if (entry is null) {
			if (_logger.IsEnabled(LogLevel.Debug)) {
				_logger.LogDebug(
					"API key not found for header {HeaderName}",
					headerName);
			}
			return Task.FromResult(ApiKeyResolveResult.NotFound());
		}

		// Convert entry to client
		var client = new ApiKeyClient {
			ClientId = entry.ClientId,
			ClientName = entry.ClientName,
			Scheme = entry.Scheme,
			Roles = entry.Roles,
			ExpiresAt = null,  // Configuration-based keys don't have expiration
			Claims = null
		};

		if (_logger.IsEnabled(LogLevel.Debug)) {
			_logger.LogDebug(
				"API key resolved successfully for header {HeaderName}: ClientId={ClientId}",
				headerName,
				client.ClientId);
		}

		return Task.FromResult(ApiKeyResolveResult.Success(client));
	}
}
