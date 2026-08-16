using Microsoft.AspNetCore.Mvc.Filters;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>
/// Marker attribute that exempts an action or controller from the package's permission/role filters
/// (in addition to the standard <c>[AllowAnonymous]</c>).
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class SkipAuthAttribute : Attribute, IFilterMetadata;
