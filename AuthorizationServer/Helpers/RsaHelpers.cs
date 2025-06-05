using System.Security.Cryptography;

namespace AuthorizationServer.Helpers
{
    public static class RsaHelpers
    {
        public static RSA LoadRsaPrivateKey(string path)
        {
            var keyText = File.ReadAllText(path);
            var rsa = RSA.Create();
            rsa.ImportFromPem(keyText.ToCharArray());
            return rsa;
        }
    }
}
