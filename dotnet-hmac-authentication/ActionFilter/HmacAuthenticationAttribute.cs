using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace dotnet_hmac_authentication.ActionFilter
{
    public class HmacAuthenticationAttribute : ActionFilterAttribute
    {
        private readonly ILogger<HmacAuthenticationAttribute> _logger;
        private readonly IConfiguration _configuration;

        public HmacAuthenticationAttribute(ILogger<HmacAuthenticationAttribute> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            try
            {
                var request = context.HttpContext.Request;

                if (request.Headers.Authorization.FirstOrDefault() is null || request.Headers.Authorization.FirstOrDefault()!.Split(' ').Length != 2)
                {
                    context.Result = new StatusCodeResult(StatusCodes.Status401Unauthorized);
                    return;
                }

                var authorizationHeader = request.Headers.Authorization.FirstOrDefault()!.Split(' ')[1];

                var host = request.Host.ToString();
                var date = request.Headers["x-ms-date"];
                var requestPayload = GetRequestPayload(request);
                var hashedBody = ComputeContentHash(requestPayload);
                var stringToSign = $"POST\n{request.Path}\n{date};{host};{hashedBody}";
                var signature = ComputeSignature(stringToSign);

                if (!IsSignatureValid(authorizationHeader, signature) || !IsHashedPayloadValid(request, hashedBody) || !IsRequestWithinAcceptableTime(request))
                {
                    context.Result = new StatusCodeResult(StatusCodes.Status401Unauthorized);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Unable authenticate request for webhook endpoint");
                context.Result = new StatusCodeResult(StatusCodes.Status500InternalServerError);
                throw;
            }

            base.OnActionExecuting(context);
        }

        private static string GetRequestPayload(HttpRequest req)
        {
            req.Body.Position = 0;
            string bodyContent = new StreamReader(req.Body).ReadToEnd();
            return bodyContent;
        }

        private static string ComputeContentHash(string content)
        {
            byte[] hashedBytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
            return Convert.ToBase64String(hashedBytes);
        }

        private string ComputeSignature(string stringToSign)
        {
            string secret = _configuration.GetSection("HmacAuthenticationKey").Value;
            using var hmacsha256 = new HMACSHA256(Convert.FromBase64String(secret));
            var bytes = Encoding.ASCII.GetBytes(stringToSign);
            var hashedBytes = hmacsha256.ComputeHash(bytes);
            return Convert.ToBase64String(hashedBytes);
        }

        private static bool IsHashedPayloadValid(HttpRequest req, string hashedBody) => hashedBody.Equals(req.Headers["x-ms-content-sha256"]);

        private static bool IsSignatureValid(string authorizationHeader, string signature) => authorizationHeader.Equals(signature);

        private static bool IsRequestWithinAcceptableTime(HttpRequest request)
        {
            if (!DateTimeOffset.TryParseExact(request.Headers["x-ms-date"], "r", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset requestDate))
                return false;

            if (requestDate > DateTimeOffset.UtcNow.Add(TimeSpan.FromMinutes(5)) || requestDate < DateTimeOffset.UtcNow.Subtract(TimeSpan.FromMinutes(5)))
                return false;

            return true;
        }
    }
}
