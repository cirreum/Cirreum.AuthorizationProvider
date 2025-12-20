namespace Cirreum.AuthorizationProvider.SignedRequest;

/// <summary>
/// Provides cryptographic signature validation and generation utilities.
/// </summary>
public interface ISignatureValidator {

	/// <summary>
	/// Validates that the provided signature matches the expected signature for the request.
	/// </summary>
	/// <param name="context">The signed request context.</param>
	/// <param name="signingSecret">The signing secret to use for validation.</param>
	/// <returns>True if the signature is valid, false otherwise.</returns>
	bool ValidateSignature(SignedRequestContext context, string signingSecret);

	/// <summary>
	/// Computes the expected signature for a request.
	/// </summary>
	/// <param name="canonicalRequest">The canonical request string to sign.</param>
	/// <param name="signingSecret">The signing secret.</param>
	/// <param name="version">The signature version (default "v1").</param>
	/// <returns>The computed signature in "version=hex" format.</returns>
	string ComputeSignature(string canonicalRequest, string signingSecret, string version = "v1");

	/// <summary>
	/// Validates that the timestamp is within the acceptable window.
	/// </summary>
	/// <param name="timestamp">The Unix timestamp from the request.</param>
	/// <returns>True if the timestamp is valid, false if expired or too far in the future.</returns>
	bool ValidateTimestamp(long timestamp);

	/// <summary>
	/// Computes the SHA256 hash of the request body.
	/// </summary>
	/// <param name="body">The request body bytes.</param>
	/// <returns>The lowercase hex-encoded SHA256 hash.</returns>
	string ComputeBodyHash(byte[] body);

	/// <summary>
	/// Computes the SHA256 hash of the request body without allocating a byte array.
	/// </summary>
	/// <param name="body">The request body bytes as a span.</param>
	/// <returns>The lowercase hex-encoded SHA256 hash.</returns>
	string ComputeBodyHash(ReadOnlySpan<byte> body);

	/// <summary>
	/// Computes the SHA256 hash of an empty body.
	/// </summary>
	/// <returns>The lowercase hex-encoded SHA256 hash of an empty string.</returns>
	string EmptyBodyHash { get; }
}
