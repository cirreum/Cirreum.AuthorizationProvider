namespace Cirreum.AuthorizationProvider.SignedRequest;

/// <summary>
/// Provides context for signed request validation, including all data needed
/// to verify the request signature.
/// </summary>
public sealed class SignedRequestContext {

	/// <summary>
	/// Initializes a new instance of the <see cref="SignedRequestContext"/> class.
	/// </summary>
	public SignedRequestContext(
		string clientId,
		string signature,
		long timestamp,
		string httpMethod,
		string path,
		string? bodyHash,
		IReadOnlyDictionary<string, string> headers) {
		ClientId = clientId;
		Signature = signature;
		Timestamp = timestamp;
		HttpMethod = httpMethod;
		Path = path;
		BodyHash = bodyHash;
		Headers = headers;
	}

	/// <summary>
	/// Gets the client ID from the X-Client-Id header.
	/// </summary>
	public string ClientId { get; }

	/// <summary>
	/// Gets the signature value from the X-Signature header.
	/// Expected format: "v1=hexstring" where v1 indicates the signature version.
	/// </summary>
	public string Signature { get; }

	/// <summary>
	/// Gets the Unix timestamp from the X-Timestamp header.
	/// </summary>
	public long Timestamp { get; }

	/// <summary>
	/// Gets the HTTP method (GET, POST, etc.).
	/// </summary>
	public string HttpMethod { get; }

	/// <summary>
	/// Gets the request path (e.g., "/api/transactions").
	/// </summary>
	public string Path { get; }

	/// <summary>
	/// Gets the SHA256 hash of the request body, or null for bodyless requests.
	/// </summary>
	public string? BodyHash { get; }

	/// <summary>
	/// Gets additional request headers for reference.
	/// </summary>
	public IReadOnlyDictionary<string, string> Headers { get; }

	/// <summary>
	/// Gets the timestamp as a DateTimeOffset.
	/// </summary>
	public DateTimeOffset TimestampAsDateTime =>
		DateTimeOffset.FromUnixTimeSeconds(Timestamp);

	/// <summary>
	/// Builds the canonical request string that should be signed.
	/// </summary>
	/// <returns>The canonical string: "{timestamp}.{method}.{path}.{bodyHash}"</returns>
	public string BuildCanonicalRequest() {
		var body = BodyHash ?? "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA256 of empty string
		return $"{Timestamp}.{HttpMethod}.{Path}.{body}";
	}

	/// <summary>
	/// Parses the signature version from the signature header value.
	/// </summary>
	/// <returns>The version string (e.g., "v1") or null if invalid format.</returns>
	public string? GetSignatureVersion() {
		var eqIndex = Signature.IndexOf('=');
		if (eqIndex <= 0) {
			return null;
		}
		return Signature[..eqIndex];
	}

	/// <summary>
	/// Gets the signature value without the version prefix.
	/// </summary>
	/// <returns>The hex-encoded signature or null if invalid format.</returns>
	public string? GetSignatureValue() {
		var eqIndex = Signature.IndexOf('=');
		if (eqIndex < 0 || eqIndex >= Signature.Length - 1) {
			return null;
		}
		return Signature[(eqIndex + 1)..];
	}
}
