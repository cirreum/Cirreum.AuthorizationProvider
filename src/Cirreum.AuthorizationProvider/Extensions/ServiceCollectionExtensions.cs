namespace Cirreum.AuthorizationProvider;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to support authorization provider registration.
/// </summary>
public static class ServiceCollectionExtensions
{
	/// <summary>
	/// Gets the <see cref="AuthorizationSchemeRegistry"/>.
	/// </summary>
	/// <param name="services">The <see cref="IServiceCollection"/>.</param>
	/// <returns>The <see cref="AuthorizationSchemeRegistry"/> instance.</returns>
	public static AuthorizationSchemeRegistry GetAuthorizationSchemeRegistry(this IServiceCollection services)
	{
		var descriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(AuthorizationSchemeRegistry));

		if (descriptor?.ImplementationInstance is AuthorizationSchemeRegistry registry)
		{
			return registry;
		}

		registry = new AuthorizationSchemeRegistry();
		services.AddSingleton(registry);
		return registry;
	}

	/// <summary>
	/// Gets the <see cref="ApiKeyClientRegistry"/>.
	/// </summary>
	/// <param name="services">The <see cref="IServiceCollection"/>.</param>
	/// <returns>The <see cref="ApiKeyClientRegistry"/> instance.</returns>
	public static ApiKeyClientRegistry GetApiKeyClientRegistry(this IServiceCollection services)
	{
		var descriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(ApiKeyClientRegistry));

		if (descriptor?.ImplementationInstance is ApiKeyClientRegistry registry)
		{
			return registry;
		}

		registry = new ApiKeyClientRegistry();
		services.AddSingleton(registry);
		return registry;
	}
}
