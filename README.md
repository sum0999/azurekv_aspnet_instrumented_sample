# KeyVaultSecretApi

A .NET 9.0 Web API for retrieving secrets from Azure Key Vault using the Azure SDK.

## Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- An Azure Key Vault instance
- A service principal with access to the Key Vault

## Configuration

Set the following values in `appsettings.json` (or via environment variables / user secrets):

```json
{
  "KeyVault": {
    "TenantId": "<your-tenant-id>",
    "ClientId": "<your-client-id>",
    "ClientSecret": "<your-client-secret>",
    "VaultUrl": "https://<your-vault-name>.vault.azure.net/"
  }
}
```

## Running

```bash
dotnet build
dotnet run
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
