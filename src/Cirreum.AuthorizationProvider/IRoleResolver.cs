namespace Cirreum.AuthorizationProvider;

/// <summary>
/// Resolves application roles for an authenticated user from the application's data store.
/// </summary>
/// <remarks>
/// <para>
/// This is the authorization system's internal contract for role resolution. The
/// <c>AudienceProviderRoleClaimsTransformer</c> calls this interface to add
/// <see cref="System.Security.Claims.ClaimTypes.Role"/> claims before ASP.NET
/// authorization policies evaluate the request.
/// </para>
/// <para>
/// Cirreum applications typically do not implement this interface directly. Instead,
/// implement <c>IApplicationUserResolver</c> (defined in Cirreum.Core) and register it
/// via <c>CirreumAuthorizationBuilder.AddApplicationUserResolver&lt;T&gt;()</c>, which
/// provides an adapter that bridges <c>IApplicationUserResolver</c> to this interface.
/// </para>
/// <para>
/// Applications that use the authorization packages independently of Cirreum.Core may
/// implement this interface directly and register via
/// <c>CirreumAuthorizationBuilder.AddRoleResolver&lt;T&gt;()</c>.
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
