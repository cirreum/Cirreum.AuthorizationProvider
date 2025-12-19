namespace Cirreum.AuthorizationProvider.SignedRequest;

/// <summary>
/// Provides hooks for signature validation events, enabling consumers to implement
/// rate limiting, alerting, and other security controls.
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface to:
/// <list type="bullet">
///   <item>Rate limit failed authentication attempts</item>
///   <item>Alert on suspicious patterns (many failures from same client)</item>
///   <item>Log detailed audit information</item>
///   <item>Block IPs or clients after threshold breaches</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// public class RateLimitingValidationEvents : ISignatureValidationEvents {
///     private readonly IRateLimiter _rateLimiter;
///
///     public async Task OnValidationFailedAsync(SignatureValidationFailedContext context) {
///         // Increment failure counter for this client
///         var key = $"sig_fail:{context.ClientId}";
///         var count = await _rateLimiter.IncrementAsync(key, TimeSpan.FromMinutes(15));
///
///         if (count > 10) {
///             // Block client temporarily
///             await _rateLimiter.BlockAsync(context.ClientId, TimeSpan.FromHours(1));
///         }
///     }
/// }
/// </code>
/// </example>
public interface ISignatureValidationEvents {

	/// <summary>
	/// Called when signature validation fails.
	/// </summary>
	/// <param name="context">Details about the failed validation.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task representing the asynchronous operation.</returns>
	Task OnValidationFailedAsync(
		SignatureValidationFailedContext context,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Called when signature validation succeeds.
	/// </summary>
	/// <param name="context">Details about the successful validation.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task representing the asynchronous operation.</returns>
	Task OnValidationSucceededAsync(
		SignatureValidationSucceededContext context,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Called before validation to check if the client is blocked.
	/// </summary>
	/// <param name="clientId">The client ID to check.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>True if the client should be blocked, false to proceed with validation.</returns>
	Task<bool> IsClientBlockedAsync(
		string clientId,
		CancellationToken cancellationToken = default);
}

/// <summary>
/// Context for a failed signature validation event.
/// </summary>
public sealed class SignatureValidationFailedContext {

	/// <summary>
	/// Gets the client ID that was attempted (may be null if header was missing).
	/// </summary>
	public string? ClientId { get; init; }

	/// <summary>
	/// Gets the type of failure that occurred.
	/// </summary>
	public required SignatureFailureType FailureType { get; init; }

	/// <summary>
	/// Gets the detailed failure reason.
	/// </summary>
	public required string FailureReason { get; init; }

	/// <summary>
	/// Gets the remote IP address of the request.
	/// </summary>
	public string? RemoteIpAddress { get; init; }

	/// <summary>
	/// Gets the request path.
	/// </summary>
	public string? RequestPath { get; init; }

	/// <summary>
	/// Gets the HTTP method.
	/// </summary>
	public string? HttpMethod { get; init; }

	/// <summary>
	/// Gets the timestamp of the failure.
	/// </summary>
	public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Context for a successful signature validation event.
/// </summary>
public sealed class SignatureValidationSucceededContext {

	/// <summary>
	/// Gets the authenticated client.
	/// </summary>
	public required SignedRequestClient Client { get; init; }

	/// <summary>
	/// Gets the credential ID that was used.
	/// </summary>
	public string? CredentialId { get; init; }

	/// <summary>
	/// Gets the remote IP address of the request.
	/// </summary>
	public string? RemoteIpAddress { get; init; }

	/// <summary>
	/// Gets the request path.
	/// </summary>
	public string? RequestPath { get; init; }

	/// <summary>
	/// Gets the HTTP method.
	/// </summary>
	public string? HttpMethod { get; init; }

	/// <summary>
	/// Gets the timestamp of the success.
	/// </summary>
	public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// A no-op implementation of <see cref="ISignatureValidationEvents"/> for when
/// consumers don't need event handling.
/// </summary>
public sealed class NullSignatureValidationEvents : ISignatureValidationEvents {

	/// <summary>
	/// Gets the singleton instance.
	/// </summary>
	public static NullSignatureValidationEvents Instance { get; } = new();

	private NullSignatureValidationEvents() { }

	/// <inheritdoc/>
	public Task OnValidationFailedAsync(
		SignatureValidationFailedContext context,
		CancellationToken cancellationToken = default) => Task.CompletedTask;

	/// <inheritdoc/>
	public Task OnValidationSucceededAsync(
		SignatureValidationSucceededContext context,
		CancellationToken cancellationToken = default) => Task.CompletedTask;

	/// <inheritdoc/>
	public Task<bool> IsClientBlockedAsync(
		string clientId,
		CancellationToken cancellationToken = default) => Task.FromResult(false);
}
