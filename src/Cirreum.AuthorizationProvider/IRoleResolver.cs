namespace Cirreum.AuthorizationProvider;

/// <summary>
/// Resolves application roles for an authenticated user from the application's data store.
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface to load the user's roles from your application's data store.
/// The resolved roles are added to the <see cref="System.Security.Claims.ClaimsPrincipal"/>
/// as <see cref="System.Security.Claims.ClaimTypes.Role"/> claims before ASP.NET authorization
/// policies and Cirreum domain authorization evaluate the request.
/// </para>
/// <para>
/// Register your implementation via <c>AddRoleResolver&lt;T&gt;()</c> on
/// <c>CirreumAuthorizationBuilder</c>. The resolver is called at most once per HTTP request;
/// the result is cached for the duration of the request via <c>HttpContext.Items</c>.
/// </para>
/// </remarks>
public interface IRoleResolver {

	/// <summary>
	/// Resolves the roles for the given external user.
	/// </summary>
	/// <param name="externalUserId">
	/// The user's identifier, sourced from the <c>oid</c>, <c>sub</c>, or <c>user_id</c>
	/// claim in the access token.
	/// </param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>
	/// One or more role strings (e.g. <c>["app:user", "app:subscriber"]</c>), or <c>null</c>
	/// if the user does not exist in the application data store. An empty list is treated
	/// the same as <c>null</c> — authorization policies that require a role will deny the request.
	/// </returns>
	Task<IReadOnlyList<string>?> ResolveRolesAsync(string externalUserId, CancellationToken cancellationToken = default);

}