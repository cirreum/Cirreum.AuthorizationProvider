namespace Cirreum.AuthorizationProvider.ApiKey;

/// <summary>
/// Provides context information for API key lookups, enabling efficient filtering
/// based on additional request data.
/// </summary>
/// <remarks>
/// <para>
/// Use this context to access additional headers that can help narrow down database queries.
/// For example, a <c>X-Client-Id</c> header can identify the partner, allowing you to query
/// only their specific key rather than all keys for a header.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// protected override Task&lt;IEnumerable&lt;StoredApiKey&gt;&gt; LookupKeysAsync(
///     string headerName,
///     ApiKeyLookupContext context,
///     CancellationToken cancellationToken) {
///
///     // Use client ID header to filter the query
///     var clientId = context.GetHeader("X-Client-Id");
///     if (!string.IsNullOrEmpty(clientId)) {
///         return _repository.FindKeyByClientIdAsync(clientId, cancellationToken);
///     }
///
///     // Fallback to returning all keys for the header
///     return _repository.FindKeysByHeaderAsync(headerName, cancellationToken);
/// }
/// </code>
/// </example>
/// <remarks>
/// Initializes a new instance of the <see cref="ApiKeyLookupContext"/> class.
/// </remarks>
/// <param name="headerName">The header name containing the API key.</param>
/// <param name="headers">All request headers (excluding the API key value for security).</param>
public sealed class ApiKeyLookupContext(
	string headerName,
	IReadOnlyDictionary<string, string> headers) {

	private readonly IReadOnlyDictionary<string, string> _headers = headers ?? new Dictionary<string, string>();

	/// <summary>
	/// Gets the HTTP header name that contained the API key.
	/// </summary>
	public string HeaderName { get; } = headerName;

	/// <summary>
	/// Gets the value of a specific header, or null if not present.
	/// </summary>
	/// <param name="headerName">The name of the header to retrieve (case-insensitive).</param>
	/// <returns>The header value, or null if not found.</returns>
	/// <remarks>
	/// Common headers to use for filtering:
	/// <list type="bullet">
	///   <item><c>X-Client-Id</c> - A public client identifier</item>
	///   <item><c>X-Tenant-Id</c> - A tenant identifier for multi-tenant scenarios</item>
	///   <item><c>X-Partner-Id</c> - A partner identifier</item>
	/// </list>
	/// </remarks>
	public string? GetHeader(string headerName) {
		return this._headers.TryGetValue(headerName, out var value) ? value : null;
	}

	/// <summary>
	/// Checks if a specific header is present in the request.
	/// </summary>
	/// <param name="headerName">The name of the header to check (case-insensitive).</param>
	/// <returns>True if the header exists, false otherwise.</returns>
	public bool HasHeader(string headerName) => this._headers.ContainsKey(headerName);

	/// <summary>
	/// Gets all available headers (excluding the API key value).
	/// </summary>
	public IReadOnlyDictionary<string, string> Headers => this._headers;
}
