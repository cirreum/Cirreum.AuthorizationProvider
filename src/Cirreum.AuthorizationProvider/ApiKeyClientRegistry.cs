namespace Cirreum.AuthorizationProvider;

using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Manages the collection of registered API key clients and provides
/// secure validation of presented keys against registered clients.
/// </summary>
public sealed class ApiKeyClientRegistry {

	private readonly List<ApiKeyClientEntry> _clients = [];

	/// <summary>
	/// Registers an API key client entry.
	/// </summary>
	/// <param name="client">The client entry to register.</param>
	public void Register(ApiKeyClientEntry client) {
		_clients.Add(client);
	}

	/// <summary>
	/// Validates a provided API key against all registered clients for the specified header.
	/// Uses constant-time comparison to prevent timing attacks.
	/// </summary>
	/// <param name="headerName">The header name the key was received on.</param>
	/// <param name="providedKey">The API key value to validate.</param>
	/// <returns>The matching client entry if valid; otherwise, <see langword="null"/>.</returns>
	public ApiKeyClientEntry? ValidateKey(string headerName, string providedKey) {
		var providedBytes = Encoding.UTF8.GetBytes(providedKey);

		foreach (var client in _clients.Where(c =>
			string.Equals(c.HeaderName, headerName, StringComparison.OrdinalIgnoreCase))) {
			var expectedBytes = Encoding.UTF8.GetBytes(client.Key);

			if (CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes)) {
				return client;
			}
		}

		return null;
	}

	/// <summary>
	/// Determines if any clients are registered for the specified header name.
	/// </summary>
	/// <param name="headerName">The header name to check.</param>
	/// <returns><see langword="true"/> if at least one client uses this header; otherwise, <see langword="false"/>.</returns>
	public bool HasHeader(string headerName) =>
		_clients.Any(c => string.Equals(c.HeaderName, headerName, StringComparison.OrdinalIgnoreCase));

	/// <summary>
	/// Gets all distinct header names that have registered clients.
	/// </summary>
	public IReadOnlySet<string> RegisteredHeaders =>
		_clients.Select(c => c.HeaderName).ToHashSet(StringComparer.OrdinalIgnoreCase);

}