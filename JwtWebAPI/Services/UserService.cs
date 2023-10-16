using System.Security.Claims;

namespace JwtWebAPI.Services
{
    public class UserService : IUserService
    {
        //permite acessar o context que é um conjunto de informaçoes
        // httpcontext gerencia e pega dados - "anotações do garçom/infos"
        private readonly IHttpContextAccessor _contextAccessor;

        public UserService(IHttpContextAccessor contextAccessor)
        {
            _contextAccessor = contextAccessor;
        }

        public string GetMyName()
        {
            var result = string.Empty;
            if(_contextAccessor != null)
            {
                result = _contextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }

            return result;
        }
    }
}
