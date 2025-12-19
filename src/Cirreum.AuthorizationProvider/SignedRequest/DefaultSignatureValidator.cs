namespace Cirreum.AuthorizationProvider.SignedRequest;

using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

/// <summary>
/// Default implementation of <see cref="ISignatureValidator"/> using HMAC-SHA256.
/// </summary>
public sealed class DefaultSignatureValidator : ISignatureValidator {

	private readonly SignatureValidationOptions _options;

	// SHA256 hash of empty string - computed once
	private static readonly string EmptyStringHash =
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	/// <summary>
	/// Initializes a new instance of the <see cref="DefaultSignatureValidator"/> class.
	/// </summary>
	/// <param name="options">The validation options.</param>
	public DefaultSignatureValidator(IOptions<SignatureValidationOptions> options) {
		_options = options?.Value ?? new SignatureValidationOptions();
	}

	/// <inheritdoc/>
	public string EmptyBodyHash => EmptyStringHash;

	/// <inheritdoc/>
	public bool ValidateSignature(SignedRequestContext context, string signingSecret) {
		var version = context.GetSignatureVersion();
		var providedSignature = context.GetSignatureValue();

		if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(providedSignature)) {
			return false;
		}

		if (!_options.SupportedSignatureVersions.Contains(version)) {
			return false;
		}

		var canonicalRequest = context.BuildCanonicalRequest();
		var expectedSignature = ComputeSignatureValue(canonicalRequest, signingSecret, version);

		// Constant-time comparison to prevent timing attacks
		return CryptographicOperations.FixedTimeEquals(
			Encoding.UTF8.GetBytes(providedSignature.ToLowerInvariant()),
			Encoding.UTF8.GetBytes(expectedSignature.ToLowerInvariant()));
	}

	/// <inheritdoc/>
	public string ComputeSignature(string canonicalRequest, string signingSecret, string version = "v1") {
		var signatureValue = ComputeSignatureValue(canonicalRequest, signingSecret, version);
		return $"{version}={signatureValue}";
	}

	/// <inheritdoc/>
	public bool ValidateTimestamp(long timestamp) {
		var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
		var now = DateTimeOffset.UtcNow;

		// Check if timestamp is too old
		var age = now - requestTime;
		if (age > _options.TimestampTolerance) {
			return false;
		}

		// Check if timestamp is too far in the future (clock skew)
		if (requestTime > now + _options.FutureTimestampTolerance) {
			return false;
		}

		return true;
	}

	/// <inheritdoc/>
	public string ComputeBodyHash(byte[] body) {
		if (body is null || body.Length == 0) {
			return EmptyStringHash;
		}

		var hash = SHA256.HashData(body);
		return Convert.ToHexString(hash).ToLowerInvariant();
	}

	/// <summary>
	/// Computes the raw signature value (without version prefix) for a canonical request.
	/// </summary>
	private static string ComputeSignatureValue(string canonicalRequest, string signingSecret, string version) {
		// v1 uses HMAC-SHA256
		// Future versions could use different algorithms
		if (version == "v1") {
			var keyBytes = Encoding.UTF8.GetBytes(signingSecret);
			var messageBytes = Encoding.UTF8.GetBytes(canonicalRequest);

			var hmac = HMACSHA256.HashData(keyBytes, messageBytes);
			return Convert.ToHexString(hmac).ToLowerInvariant();
		}

		throw new NotSupportedException($"Signature version '{version}' is not supported");
	}
}
