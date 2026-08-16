# FronteggAuth.AspNetCore.DataProtection.Aws

Optional companion to [`FronteggAuth.AspNetCore`](https://www.nuget.org/packages/FronteggAuth.AspNetCore).
It persists the ASP.NET Core Data Protection key ring to **AWS Systems Manager Parameter Store**.

You need this (or another shared key-ring store) whenever more than one process serves the same
authentication cookie. Data Protection's default store is the local file system, so a second instance
cannot decrypt the first's cookie and the user is bounced back to the login page.

The core package has no AWS dependency — install this one only if you want the SSM store.

```bash
dotnet add package FronteggAuth.AspNetCore.DataProtection.Aws
```

```csharp
using FronteggAuth.AspNetCore.DataProtection.Aws;

builder.Services.AddFronteggAuth(builder.Configuration, options =>
{
    options.PersistDataProtectionKeysToSsm("/myapp/{environment}/dataprotection");
});
```

`{environment}` is replaced with the lower-cased value of `ASPNETCORE_ENVIRONMENT` (`production` when
unset), so one configured path serves every environment.

The application's AWS credentials need `ssm:GetParametersByPath` and `ssm:PutParameter` on that path.
Keys are stored as `SecureString` parameters; grant `kms:Decrypt`/`kms:Encrypt` for the key that protects
them.

Any other `IDataProtectionBuilder` persistence provider works without this package — set
`FronteggSettings.ConfigureDataProtection` directly:

```csharp
options.ConfigureDataProtection = dp => dp.PersistKeysToAzureBlobStorage(blobUri, credential);
```

Licensed under the MIT License.
