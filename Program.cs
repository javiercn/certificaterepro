using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace certificaterepro
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Choose step:");
            var stage = args.Length == 0 ? Console.ReadLine() : args[0];
            switch (int.Parse(stage))
            {
                case 1:
                    var time = DateTimeOffset.Now.AddMinutes(-5);
                    var cert = Helpers.CreateAspNetCoreHttpsDevelopmentCertificate(time, time.AddHours(1));

                    // Save certificate
                    var export = cert.Export(X509ContentType.Pkcs12, "");
                    cert = new X509Certificate2(export, "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                    Array.Clear(export, 0, export.Length);
                    cert.FriendlyName = "Localhost test";

                    using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                    {
                        store.Open(OpenFlags.ReadWrite);
                        store.Add(cert);
                        store.Close();
                    }
                    break;
                case 2:
                    var cert2 = Helpers.ListCertificates().Single(c => IsExportable(c));
                    // Export certificate
                    var targetDirectoryPath = Directory.GetCurrentDirectory();
                    var path = Path.Combine(targetDirectoryPath, "cert.pfx");

                    byte[] bytes;
                    bytes = cert2.Export(X509ContentType.Pkcs12, "asdf");
                    File.WriteAllBytes(path, bytes);
                    Array.Clear(bytes, 0, bytes.Length);
                    IsExportable(cert2);
                    // Trust certificate
                    IsExportable(cert2);
                    var publicCertificate = new X509Certificate2(cert2.Export(X509ContentType.Cert));

                    publicCertificate.FriendlyName = cert2.FriendlyName;

                    using (var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
                    {

                        store.Open(OpenFlags.ReadWrite);
                        var existing = store.Certificates.Find(X509FindType.FindByThumbprint, publicCertificate.Thumbprint, validOnly: false);
                        if (existing.Count > 0)
                        {
                            Console.WriteLine("Already trusted!");
                        }
                        else
                        {
                            store.Add(publicCertificate);
                            store.Close();
                        }
                    }
                    break;
                case 3:
                    var cert3 = Helpers.ListCertificates().Single();
                    if (cert3.GetRSAPrivateKey() is RSACryptoServiceProvider rsa)
                    {
                        Console.WriteLine(rsa?.CspKeyContainerInfo.Exportable);
                    }
                    if (cert3.GetRSAPrivateKey() is RSACng cngPrivateKey)
                    {
                        Console.WriteLine(cngPrivateKey?.Key.ExportPolicy);
                    }
                    break;
            }
        }

        internal static bool IsExportable(X509Certificate2 c)
        {
            return (c.GetRSAPrivateKey() is RSACryptoServiceProvider rsaPrivateKey &&
                    rsaPrivateKey.CspKeyContainerInfo.Exportable) ||
                (c.GetRSAPrivateKey() is RSACng cngPrivateKey &&
                    cngPrivateKey.Key.ExportPolicy == CngExportPolicies.AllowExport);
        }

        internal static string GetDescription(X509Certificate2 c)
        {
            return $"{c.Thumbprint[0..6]} - {c.Subject} - {c.GetEffectiveDateString()} - {c.GetExpirationDateString()} - {IsHttpsDevelopmentCertificate(c)} - {IsExportable(c)}";
        }

        public static bool IsHttpsDevelopmentCertificate(X509Certificate2 certificate) =>
            certificate.Extensions.OfType<X509Extension>()
            .Any(e => string.Equals("1.3.6.1.4.1.311.84.1.2", e.Oid.Value, StringComparison.Ordinal));
    }
}