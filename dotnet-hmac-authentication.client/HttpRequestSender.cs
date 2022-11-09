using dotnet_hmac_authentication.client.DelegationHandler;
using System.Net;
using System.Text;

namespace dotnet_hmac_authentication.client
{
    public class HttpRequestSender
    {
        public static async Task SendAsync()
        {
            var content = new StringContent("stringPayload", Encoding.UTF8, "application/json");

            var _httpClient = HttpClientFactory.Create(new HmacDelegatingHandler());

            var response = await _httpClient.PostAsync("webhookurl", content);

            if (!response.IsSuccessStatusCode)
                throw new InvalidResponseException { StatusCode = HttpStatusCode.Forbidden };
        }

        public class InvalidResponseException : Exception
        {
            public HttpStatusCode StatusCode { get; set; }
        }
    }
}
