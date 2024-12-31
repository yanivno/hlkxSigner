using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using DotNetEnv;

public class KeyVaultCertificateRetriever
{
    private static async Task<X509Certificate2> GetCertificateWithPrivateKeyFromKeyVaultAsync(string keyVaultUrl, string certificateName)
    {
        var certificateClient = new CertificateClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
        var secretClient = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

        KeyVaultCertificateWithPolicy certificate = await certificateClient.GetCertificateAsync(certificateName);
        KeyVaultSecret secret = await secretClient.GetSecretAsync(certificateName);

        byte[] privateKeyBytes = Convert.FromBase64String(secret.Value);
        return new X509Certificate2(privateKeyBytes, (string)null, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
    }

    public static async Task Main(string[] args)
    {
        Env.TraversePath().Load(); 
        
        string keyVaultUrl = Environment.GetEnvironmentVariable("KEYVAULT_URL");
        string certificateName = Environment.GetEnvironmentVariable("KEYVAULT_CERTIFICATE_NAME");
        Console.WriteLine($"Retrieving certificate from Key Vault: {keyVaultUrl} with name: {certificateName}");

        X509Certificate2 certificate = await GetCertificateWithPrivateKeyFromKeyVaultAsync(keyVaultUrl, certificateName);
        Console.WriteLine($"Retrieved certificate with subject: {certificate.Subject}");

        string packagePath = Environment.GetEnvironmentVariable("PACKAGE_PATH");
        Console.WriteLine($"Signing package: {packagePath}");
        // Use the certificate as needed
        Signer.Sign(packagePath, certificate);
    }
}