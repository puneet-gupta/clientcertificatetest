using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace clientcertificatetest
{
    public class CertificateWebClient : WebClient
    {
        private readonly X509Certificate2 certificate;

        public CertificateWebClient(X509Certificate2 cert)
        {
            certificate = cert;
        }

        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request = (HttpWebRequest)base.GetWebRequest(address);

            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate(Object obj, X509Certificate X509certificate, X509Chain chain, System.Net.Security.SslPolicyErrors errors)
            {
                return true;
            };

            request.ClientCertificates.Add(certificate);
            return request;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length !=2)
            {
                Console.WriteLine("Please pass the URL of the Azure WebApp that you want to call");
            }
            else
            {
                string webAppUrl = args[0];
                string certThumbPrint = args[1];

                
                X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);

                certStore.Open(OpenFlags.ReadOnly);
                // Find the certificate that matches the thumbprint.
                X509Certificate2Collection certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, certThumbPrint, false);
                certStore.Close();

                if (0 == certCollection.Count)
                {
                    Console.WriteLine("Error: No certificate found containing thumbprint ");
                }
                else
                {
                    PrintCertProperties(certCollection[0]);

                    // Create a new WebClient instance.
                    CertificateWebClient myWebClient = new CertificateWebClient(certCollection[0]);
                    string response = myWebClient.DownloadString(webAppUrl);

                    Console.WriteLine("Response received from call to URL {0}", webAppUrl);
                    Console.WriteLine(response.Replace("<br/>", Environment.NewLine));
                }
                
            }
        }

        private static void PrintCertProperties(X509Certificate2 x509Certificate2)
        {
            Console.WriteLine("Client Certificate Properties");
            Console.WriteLine("=======================================");
            Console.WriteLine("Issuer {0}" , x509Certificate2.IssuerName.Name);
            Console.WriteLine("SubjectName {0}", x509Certificate2.SubjectName.Name);
            Console.WriteLine("Thumbprint {0}", x509Certificate2.Thumbprint);
            Console.WriteLine("HasPrivateKey {0}", x509Certificate2.HasPrivateKey);
            Console.WriteLine("isPrivateKeyExportable {0}", isPrivateKeyExportable(x509Certificate2));
            Console.WriteLine("Issuer {0}", x509Certificate2.IssuerName.Name);
        }

        private static bool isPrivateKeyExportable(X509Certificate2 col1)
        {
            bool _exportable = false;

            try
            {
                ICspAsymmetricAlgorithm key = (ICspAsymmetricAlgorithm)col1.PrivateKey;
                if (key != null)
                {
                    _exportable = key.CspKeyContainerInfo.Exportable;
                }
            }
            catch { }

            return _exportable;
        }
    }
}
