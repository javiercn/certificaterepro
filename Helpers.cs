
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace certificaterepro
{
    public static class Helpers
    {
        internal static X509Certificate2 CreateAspNetCoreHttpsDevelopmentCertificate(DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var subject = new X500DistinguishedName("CN=localhost.repro");
            var extensions = new List<X509Extension>();
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost.repro");

            var keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, critical: true);
            var enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
                new OidCollection() {
                    new Oid(
                        "1.3.6.1.5.5.7.3.1",
                        "Server Authentication")
                },
                critical: true);

            var basicConstraints = new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true);

            var bytePayload = Encoding.ASCII.GetBytes("ASP.NET Core HTTPS development certificate");

            var aspNetHttpsExtension = new X509Extension(
                new AsnEncodedData(
                    new Oid("1.3.6.1.4.1.311.84.1.2", "ASP.NET Core HTTPS development certificate"),
                    bytePayload),
                critical: false);

            extensions.Add(basicConstraints);
            extensions.Add(keyUsage);
            extensions.Add(enhancedKeyUsage);
            extensions.Add(sanBuilder.Build(critical: true));
            extensions.Add(aspNetHttpsExtension);

            var certificate = CreateSelfSignedCertificate(subject, extensions, notBefore, notAfter);
            return certificate;
        }

        internal static X509Certificate2 CreateSelfSignedCertificate(
            X500DistinguishedName subject,
            IEnumerable<X509Extension> extensions,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter)
        {
            var key = CreateKeyMaterial(2048);

            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            foreach (var extension in extensions)
            {
                request.CertificateExtensions.Add(extension);
            }

            var result = request.CreateSelfSigned(notBefore, notAfter);
            return result;

            RSA CreateKeyMaterial(int minimumKeySize)
            {
                var rsa = RSA.Create(minimumKeySize);
                if (rsa.KeySize < minimumKeySize)
                {
                    throw new InvalidOperationException($"Failed to create a key with a size of {minimumKeySize} bits");
                }

                return rsa;
            }
        }

        public static IList<X509Certificate2> ListCertificates()
        {
            var certificates = new List<X509Certificate2>();
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            certificates.AddRange(store.Certificates.OfType<X509Certificate2>());
            IEnumerable<X509Certificate2> matchingCertificates = certificates;
            matchingCertificates = matchingCertificates
                .Where(c => HasOid(c, "1.3.6.1.4.1.311.84.1.2"));

            var now = DateTimeOffset.Now;
            var validCertificates = matchingCertificates
                .Where(c => IsExportable(c))
                .ToArray();

            matchingCertificates = validCertificates;

            // We need to enumerate the certificates early to prevent disposing issues.
            matchingCertificates = matchingCertificates.ToList();

            var certificatesToDispose = certificates.Except(matchingCertificates);
            DisposeCertificates(certificatesToDispose);
            store.Close();

            return (IList<X509Certificate2>)matchingCertificates;

            bool HasOid(X509Certificate2 certificate, string oid) =>
                certificate.Extensions.OfType<X509Extension>()
                    .Any(e => string.Equals(oid, e.Oid.Value, StringComparison.Ordinal));
        }

        private static bool IsExportable(X509Certificate2 c)
        {
            return (c.GetRSAPrivateKey() is RSACryptoServiceProvider rsaPrivateKey &&
                    rsaPrivateKey.CspKeyContainerInfo.Exportable) ||
                (c.GetRSAPrivateKey() is RSACng cngPrivateKey &&
                    cngPrivateKey.Key.ExportPolicy == CngExportPolicies.AllowExport);
        }

        internal static void DisposeCertificates(IEnumerable<X509Certificate2> disposables)
        {
            foreach (var disposable in disposables)
            {
                try
                {
                    disposable.Dispose();
                }
                catch
                {
                }
            }
        }

    }
}