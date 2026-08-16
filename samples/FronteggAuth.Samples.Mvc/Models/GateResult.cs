namespace FronteggAuth.Samples.Mvc.Models;

/// <summary>
/// What a reader needs in order to understand why an action rendered: the gate it carries and what that gate
/// means. Every action in <c>ReportsController</c> returns one of these into a single shared view.
/// </summary>
/// <param name="Action">Action name, as the reader typed it in the address bar.</param>
/// <param name="Gate">The attribute(s) applied, verbatim.</param>
/// <param name="Explanation">Why reaching this page proves something.</param>
public sealed record GateResult(string Action, string Gate, string Explanation);
