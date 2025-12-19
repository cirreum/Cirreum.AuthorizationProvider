namespace Cirreum.AuthorizationProvider.SignedRequest;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Base class for implementing database-backed or external signed request resolvers.
/// Handles common concerns like timestamp validation, signature verification, and expiration checking.
/// </summary>
/// <remarks>
/// <para>
/// Inherit from this class to create a custom resolver. You only need to implement:
/// <list type="bullet">
///   <item><see cref="LookupCredentialsAsync"/> - your database/external lookup logic</item>
/// </list>
/// </para>
/// <para>
/// The base class handles timestamp validation, signature computation and comparison,
/// expiration checking, and result construction.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// public class MyDatabaseResolver : DynamicSignedRequestClientResolver {
///     private readonly ICredentialRepository _repository;
///
///     public MyDatabaseResolver(
///         ICredentialRepository repository,
///         ISignatureValidator validator,
///         IOptions&lt;SignatureValidationOptions&gt; options,
///         ILogger&lt;MyDatabaseResolver&gt; logger)
///         : base(validator, options, logger) {
///         _repository = repository;
///     }
///
///     protected override Task&lt;IEnumerable&lt;StoredSigningCredential&gt;&gt; LookupCredentialsAsync(
///         string clientId,
///         CancellationToken cancellationToken) {
///         return _repository.FindActiveCredentialsByClientIdAsync(clientId, cancellationToken);
///     }
/// }
/// </code>
/// </example>
/// <remarks>
/// Initializes a new instance of the <see cref="DynamicSignedRequestClientResolver"/> class.
/// </remarks>
/// <param name="validator">The signature validator.</param>
/// <param name="options">The validation options.</param>
/// <param name="logger">The logger instance.</param>
public abstract class DynamicSignedRequestClientResolver(
	ISignatureValidator validator,
	IOptions<SignatureValidationOptions> options,
	ILogger logger) : ISignedRequestClientResolver {

	private readonly ISignatureValidator _validator = validator ?? throw new ArgumentNullException(nameof(validator));
	private readonly SignatureValidationOptions _options = options?.Value ?? new SignatureValidationOptions();
	private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));

	/// <summary>
	/// Looks up stored signing credentials from the database or external source.
	/// </summary>
	/// <param name="clientId">The client ID to look up.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>
	/// The stored credentials for the given client, or an empty collection if none exist.
	/// Multiple credentials may be returned to support key rotation.
	/// </returns>
	/// <remarks>
	/// <para>
	/// Return all active credentials for the client. The base class will try each one
	/// until it finds a matching signature, enabling zero-downtime key rotation.
	/// </para>
	/// <para>
	/// The query should be efficient - lookup by client ID should hit an index.
	/// </para>
	/// </remarks>
	protected abstract Task<IEnumerable<StoredSigningCredential>> LookupCredentialsAsync(
		string clientId,
		CancellationToken cancellationToken);

	/// <inheritdoc/>
	public async Task<SignedRequestValidationResult> ValidateAsync(
		SignedRequestContext context,
		CancellationToken cancellationToken = default) {

		// 1. Validate signature format
		var version = context.GetSignatureVersion();
		if (string.IsNullOrEmpty(version)) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"Invalid signature format for client {ClientId}",
					context.ClientId);
			}
			return SignedRequestValidationResult.InvalidSignatureFormat("Missing version prefix");
		}

		if (!this._options.SupportedSignatureVersions.Contains(version)) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"Unsupported signature version {Version} for client {ClientId}",
					version,
					context.ClientId);
			}
			return SignedRequestValidationResult.InvalidSignatureFormat($"Unsupported version: {version}");
		}

		// 2. Validate timestamp
		if (!this._validator.ValidateTimestamp(context.Timestamp)) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"Timestamp validation failed for client {ClientId}: {Timestamp}",
					context.ClientId,
					context.TimestampAsDateTime);
			}
			return SignedRequestValidationResult.TimestampExpired();
		}

		// 3. Lookup credentials
		IEnumerable<StoredSigningCredential> credentials;
		try {
			credentials = await this.LookupCredentialsAsync(context.ClientId, cancellationToken);
		} catch (Exception ex) {
			if (this._logger.IsEnabled(LogLevel.Error)) {
				this._logger.LogError(ex,
					"Error looking up credentials for client {ClientId}",
					context.ClientId);
			}
			return SignedRequestValidationResult.Failed("Credential lookup failed");
		}

		// 4. Try each credential until we find a match (supports key rotation)
		StoredSigningCredential? matchedCredential = null;

		foreach (var credential in credentials) {
			// Skip inactive credentials
			if (!credential.IsActive) {
				continue;
			}

			// Check expiration
			if (credential.ExpiresAt.HasValue && credential.ExpiresAt.Value < DateTimeOffset.UtcNow) {
				if (this._logger.IsEnabled(LogLevel.Debug)) {
					this._logger.LogDebug(
						"Credential {CredentialId} for client {ClientId} has expired",
						credential.CredentialId,
						context.ClientId);
				}
				continue;
			}

			// Validate signature
			if (this._validator.ValidateSignature(context, credential.SigningSecret)) {
				matchedCredential = credential;
				break;
			}
		}

		if (matchedCredential is null) {
			// Check if we found any credentials at all
			var hasAnyCredentials = credentials.Any();

			if (!hasAnyCredentials) {
				if (this._logger.IsEnabled(LogLevel.Debug)) {
					this._logger.LogDebug(
						"No credentials found for client {ClientId}",
						context.ClientId);
				}
				return SignedRequestValidationResult.ClientNotFound();
			}

			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"Invalid signature for client {ClientId}",
					context.ClientId);
			}
			return SignedRequestValidationResult.InvalidSignature();
		}

		// 5. Success - build client
		var client = matchedCredential.ToClient();

		if (this._logger.IsEnabled(LogLevel.Debug)) {
			this._logger.LogDebug(
				"Signed request validated for client {ClientId} ({ClientName}) using credential {CredentialId}",
				client.ClientId,
				client.ClientName,
				matchedCredential.CredentialId);
		}

		return SignedRequestValidationResult.Success(client);
	}
}
