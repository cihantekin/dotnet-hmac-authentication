using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace dotnet_hmac_authentication.client.DelegationHandler
{
    public class HmacDelegatingHandler : DelegatingHandler
    {
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                var date = DateTimeOffset.UtcNow.ToString("r", CultureInfo.InvariantCulture);
                var host = request.RequestUri.Authority;
                var contentHash = ComputeContentHash(await request.Content.ReadAsStringAsync(cancellationToken));
                var stringToSign = $"POST\n{request.RequestUri.PathAndQuery}\n{date};{host};{contentHash}";
                var signature = ComputeSignature(stringToSign);
                var authorizationHeader = new AuthenticationHeaderValue("HMAC-SHA256", signature);

                request.Headers.Add("x-ms-date", date);
                request.Headers.Add("x-ms-content-sha256", contentHash);
                request.Headers.Authorization = authorizationHeader;

                HttpResponseMessage response = await base.SendAsync(request, cancellationToken);
                return response;
            }
            catch (Exception ex)
            {
                HttpResponseMessage response = await base.SendAsync(request, cancellationToken);
                return response;
            }
        }

        private static string ComputeContentHash(string content)
        {
            using var sha256 = SHA256.Create();
            byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
            return Convert.ToBase64String(hashedBytes);
        }

        private static string ComputeSignature(string stringToSign)
        {
            string secret = "MYSECRETKEY1";
            using var hmacsha256 = new HMACSHA256(Convert.FromBase64String(secret));
            var bytes = Encoding.ASCII.GetBytes(stringToSign);
            var hashedBytes = hmacsha256.ComputeHash(bytes);
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
