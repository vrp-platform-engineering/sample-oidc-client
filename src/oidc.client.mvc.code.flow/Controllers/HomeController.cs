using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using oidc.client.mvc.code.flow.Support.IOC;
using oidc.client.mvc.code.flow.Support.Models;
using oidc.client.mvc.code.flow.Support.Utilities;

namespace oidc.client.mvc.code.flow.Controllers
{
    public class HomeController : Controller
    {
        #region ...

        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        #endregion

        public async Task<IActionResult> GetAccessToken()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token") ?? "No access token";
            var idToken = await HttpContext.GetTokenAsync("id_token") ?? "No ID token";

            var claims = TokenUtilities.GetClaimsSummary(accessToken);

            ViewBag.Json = JsonUtilities.Beautify(JsonUtilities.Serialize(claims));
            return View("Data_json");
        }

        public async Task<IActionResult> GetIdToken()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token") ?? "No access token";
            var idToken = await HttpContext.GetTokenAsync("id_token") ?? "No ID token";

            var claims = TokenUtilities.GetClaimsSummary(idToken);

            ViewBag.Json = JsonUtilities.Beautify(JsonUtilities.Serialize(claims));
            return View("Data_json");
        }

        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
            if (string.IsNullOrEmpty(refreshToken))
            {
                ViewBag.Error = "No refresh token found.";
                return View("Data_json");
            }

            // Get OIDC configuration
            var authority = _configuration["Security:OIDC:Authority"] ?? "https://localhost:7001";
            var clientId = _configuration["Security:OIDC:ClientId"] ?? "client.001";
            var clientSecret = _configuration["Security:OIDC:ClientSecret"];
            var skipCertificateValidation = _configuration.GetValue<bool>("Security:OIDC:SkipOIDCServerCertificateCheck", false);
            var certConfig = _configuration.GetSection("Security:OIDC:ClientCertificate").Get<ClientCertificateConfiguration>();
            X509Certificate2? certificate = SecurityIOCHelpers.LoadCertificateFromConfig(certConfig);

            var result = await OIDCUtilities.RefreshToken(HttpContext, authority, clientId, clientSecret, certificate, refreshToken, skipCertificateValidation);

            ViewBag.Json = JsonUtilities.Beautify(JsonUtilities.Serialize(result));

            return View("Data_json");
        }

        public IActionResult Logout()
        {
            return SignOut(CookieAuthenticationDefaults.AuthenticationScheme, 
                           OpenIdConnectDefaults.AuthenticationScheme);
        }
    }
}
