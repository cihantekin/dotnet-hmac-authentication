using dotnet_hmac_authentication.client.DelegationHandler;
using Newtonsoft.Json;
using System.Net;
using System.Text;

namespace dotnet_hmac_authentication.client
{
    public class HttpRequestSender
    {
        public async Task SendAsync()
        {
            WeatherForecast weatherForecast = new()
            {
                Date = DateOnly.MinValue,
                Payload = "test",
                Summary = "test",
                TemperatureC = 32
            }; 

            var content = new StringContent(JsonConvert.SerializeObject(weatherForecast), Encoding.UTF8, "application/json");

            var _httpClient = HttpClientFactory.Create(new HmacDelegatingHandler());

            var response = await _httpClient.PostAsync("https://localhost:7068/WeatherForecast", content);

            if (!response.IsSuccessStatusCode)
                throw new InvalidResponseException { StatusCode = HttpStatusCode.Forbidden };
        }

        public class InvalidResponseException : Exception
        {
            public HttpStatusCode StatusCode { get; set; }
        }
    }
}
