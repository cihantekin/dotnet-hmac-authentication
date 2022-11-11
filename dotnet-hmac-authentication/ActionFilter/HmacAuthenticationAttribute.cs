using Microsoft.AspNetCore.Mvc.Filters;

namespace dotnet_hmac_authentication.ActionFilter
{
    public class HmacAuthenticationAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            base.OnActionExecuting(context);
        }
    }
}
