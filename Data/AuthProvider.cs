using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace Blazor.CustomAuth.Data
{
    public class AuthProvider : AuthenticationStateProvider
    {
        private ProtectedSessionStorage _sessionStorage;

        public AuthProvider(ProtectedSessionStorage sessionStorage)
        {
            _sessionStorage = sessionStorage;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {


            ClaimsIdentity identity = new ClaimsIdentity(null, "serverAuth");

            var result = await _sessionStorage.GetAsync<User>("authKey");
            if (result.Success)
            {
                identity.AddClaim(new Claim(ClaimTypes.Name, result.Value.Username));
            }
            else
            {
                identity = new ClaimsIdentity();
            }

            ClaimsPrincipal user = new ClaimsPrincipal(identity);
            return await Task.FromResult(new AuthenticationState(user));
        }

    }
}