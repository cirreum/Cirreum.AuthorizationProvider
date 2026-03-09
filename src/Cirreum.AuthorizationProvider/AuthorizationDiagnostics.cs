namespace Cirreum.AuthorizationProvider;

/// <summary>
/// Diagnostic constants for the Authorization Provider telemetry.
/// The ActivitySource and Meter are created in the Runtime layer;
/// this class exposes the shared name so both layers agree on the identifier.
/// </summary>
public static class AuthorizationDiagnostics {

	/// <summary>
	/// Diagnostic name for the ActivitySource and Meter. Referenced by the Runtime layer to subscribe to telemetry.
	/// </summary>
	public const string DiagnosticName = "Cirreum.AuthorizationProvider";

}
