namespace Cirreum.AuthorizationProvider.ApiKey;

/// <summary>
/// Represents an authenticated API key client with its associated identity and permissions.
/// </summary>
public sealed record ApiKeyClient {

	/// <summary>
	/// Gets the unique identifier for this client.
	/// </summary>
	public required string ClientId { get; init; }

	/// <summary>
	/// Gets the display name for this client.
	/// </summary>
	public required string ClientName { get; init; }

	/// <summary>
	/// Gets the authentication scheme name for this client.
	/// </summary>
	public required string Scheme { get; init; }

	/// <summary>
	/// Gets the roles assigned to this client.
	/// </summary>
	public IReadOnlyList<string> Roles { get; init; } = [];

	/// <summary>
	/// Gets the optional expiration time for this client's API key.
	/// </summary>
	public DateTimeOffset? ExpiresAt { get; init; }

	/// <summary>
	/// Gets optional custom claims to include in the client's identity.
	/// </summary>
	public IReadOnlyDictionary<string, string>? Claims { get; init; }
}
