using System.Security.Claims;

namespace CreateJsonWebToken.Services.UserService
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor httpContextAccessor;

        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            this.httpContextAccessor = httpContextAccessor;
        }

        public string GetClaims()
        {
            var result = string.Empty;
            if(httpContextAccessor.HttpContext != null)
            {
                result = httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
                return result;
            }
            return null;
            
        }
    }
}
