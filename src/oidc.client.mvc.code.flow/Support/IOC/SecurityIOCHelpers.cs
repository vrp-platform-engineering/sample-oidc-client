using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using oidc.client.mvc.code.flow.Support.Models;

namespace oidc.client.mvc.code.flow.Support.IOC
{
    public static class SecurityIOCHelpers
    {
        public static AuthenticationBuilder AddAuthenticationSupport(this IServiceCollection services, IConfiguration configuration)
        {
            var oidcConfig = configuration.GetSection(Constants.Constants.ConfigSecurityOIDCTag).Get<OIDCConfiguration>();

            JwtSecurityTokenHandler.DefaultMapInboundClaims = oidcConfig.JwtSecurityTokenMapInboundClaims ?? false;

            return services.AddAuthentication(options =>
                            {
                                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                            })

                           .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                           {
                               options.Cookie.Name = oidcConfig.CookieName;
                               options.Cookie.SameSite = SameSiteMode.None;
                           })

                           .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                           {
                               #region ..

                               if (oidcConfig.SkipOIDCServerCertificateCheck == true)
                               {
                                   options.BackchannelHttpHandler = new HttpClientHandler()
                                   {
                                       ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                                   };
                               }

                               #endregion

                               options.Authority = oidcConfig.Authority;
                               options.RequireHttpsMetadata = oidcConfig.RequireHttpsMetadata ?? false;

                               options.ClientId = oidcConfig.ClientId;
                               options.ClientSecret = oidcConfig.ClientSecret;
                               options.ResponseType = oidcConfig.ResponseType;
                               options.SaveTokens = oidcConfig.SaveTokens ?? true;
                               options.UsePkce = oidcConfig.UsePkce ?? true; // PKCE enabled by default; set to false in appsettings to disable
                               
                               // Configure callback paths
                               options.SignedOutCallbackPath = "/signout-callback-oidc";

                               oidcConfig.Scopes?.ForEach(x => options.Scope.Add(x));

                               options.ClaimActions.MapJsonKey(Constants.Constants.OidcTokenValidationClaimRole,
                                                               Constants.Constants.OidcTokenValidationClaimRole,
                                                               Constants.Constants.OidcTokenValidationClaimRole);

                               options.GetClaimsFromUserInfoEndpoint = true;

                              options.TokenValidationParameters = new TokenValidationParameters
                              {
                                  NameClaimType = Constants.Constants.OidcTokenValidationClaimName,
                                  RoleClaimType = Constants.Constants.OidcTokenValidationClaimRole,
                                  
                                  // JWT Signature Validation
                                  ValidateIssuer = true,
                                  ValidIssuer = oidcConfig.Authority,
                                  ValidIssuers = new[] { oidcConfig.Authority, $"{oidcConfig.Authority}/" }, // Handle trailing slash
                                  
                                  ValidateAudience = true,
                                  ValidAudience = oidcConfig.ClientId,
                                  
                                  ValidateIssuerSigningKey = true,
                                  // Signing keys are automatically fetched from JWKS endpoint
                                  
                                  ValidateLifetime = true,
                                  ClockSkew = TimeSpan.FromMinutes(5),
                                  
                                  RequireSignedTokens = true
                              };

                               options.Events = new OpenIdConnectEvents
                               {
                                   OnMessageReceived = context => OnMessageReceived(context, oidcConfig),
                                   OnRedirectToIdentityProvider = context => OnRedirectToIdentityProvider(context, oidcConfig),
                                   OnAuthorizationCodeReceived = context => OnAuthorizationCodeReceived(context, oidcConfig),
                                   OnRedirectToIdentityProviderForSignOut = context => OnRedirectToIdentityProviderForSignOut(context, oidcConfig),
                                   OnSignedOutCallbackRedirect = context => OnSignedOutCallbackRedirect(context),
                                   OnRemoteFailure = context => OnRemoteFailure(context)
                               };
                           });
        }

        public static X509Certificate2? GetX509CertificateFromFile(string filePath, string password)
        {
            var certificatePath = Path.Combine(Directory.GetCurrentDirectory(), filePath);
            if (!File.Exists(certificatePath))
            {
                if (File.Exists(filePath))
                {
                    certificatePath = filePath;
                }
                else
                {
                    throw new FileNotFoundException($"Certificate file not found at: {certificatePath} or {filePath}");
                }
            }

            return new X509Certificate2(certificatePath, password);
        }

        public static X509Certificate2 GetX509CertificateFromBase64(string base64Content, string password)
        {
            if (string.IsNullOrWhiteSpace(base64Content))
                throw new ArgumentException("Base64 certificate content cannot be empty", nameof(base64Content));

            var certBytes = Convert.FromBase64String(base64Content);
            return new X509Certificate2(certBytes, password);
        }

        public static X509Certificate2? LoadCertificateFromConfig(ClientCertificateConfiguration certConfig)
        {
            if (certConfig == null) return null;

            if (!string.IsNullOrEmpty(certConfig.CertificateBase64))
            {
                return GetX509CertificateFromBase64(certConfig.CertificateBase64, certConfig.CertificatePassword);
            }

            if (!string.IsNullOrEmpty(certConfig.CertificatePath))
            {
                return GetX509CertificateFromFile(certConfig.CertificatePath, certConfig.CertificatePassword);
            }

            return null;
        }

        public static string GenerateClientAssertion(X509Certificate2 certificate, string clientId, string authority)
        {
            var now = DateTime.UtcNow;

            // Explicitly specify RS256
            var credentials = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);

            var header = new JwtHeader(credentials);
            // OpenIddict 7.x requires "client-authentication+jwt" type header (per OAuth 2.0 spec update)
            // This is a breaking change from OpenIddict 5.x which accepted "JWT"
            header[JwtHeaderParameterNames.Typ] = "client-authentication+jwt";
            header[JwtHeaderParameterNames.Kid] = certificate.Thumbprint;

            // For token endpoint: Audience MUST be the Issuer URI (OpenIddict 7.x change)
            // OpenIddict 7.0 no longer supports token_endpoint as audience for token endpoint requests
            var aud = authority.EndsWith("/") ? authority : authority + "/";

            var payload = new JwtPayload
            (
                issuer: clientId,
                audience: aud,
                claims: new[]
                {
                    new Claim(JwtRegisteredClaimNames.Iss, clientId),
                    new Claim(JwtRegisteredClaimNames.Sub, clientId),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                },
                notBefore: now.AddMinutes(-5),
                expires: now.AddMinutes(5)
            );

            var token = new JwtSecurityToken(header, payload);
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenString = tokenHandler.WriteToken(token);

            Console.WriteLine($"[SecurityIOCHelpers] Generated Client Assertion: {tokenString}");
            return tokenString;
        }

        #region ..

        private static Task OnMessageReceived(MessageReceivedContext context, OIDCConfiguration oidcConfig)
        {
            context.Properties.IsPersistent = true;
            context.Properties.ExpiresUtc = new DateTimeOffset(DateTime.Now.AddMinutes(oidcConfig.CookieExpiresInMinutes ?? 60));

            return Task.FromResult(0);
        }
        private static Task OnRedirectToIdentityProvider(RedirectContext context, OIDCConfiguration oidcConfig)
        {
            context.ProtocolMessage.RedirectUri = oidcConfig.RedirectUri;

            return Task.FromResult(0);
        }

        private static Task OnRedirectToIdentityProviderForSignOut(RedirectContext context, OIDCConfiguration oidcConfig)
        {
            // Configure post-logout redirect URI
            if (!string.IsNullOrEmpty(oidcConfig.PostLogoutRedirectUri))
            {
                context.ProtocolMessage.PostLogoutRedirectUri = oidcConfig.PostLogoutRedirectUri;
            }

            return Task.FromResult(0);
        }

        private static Task OnSignedOutCallbackRedirect(RemoteSignOutContext context)
        {
            // After sign-out callback is processed, redirect to home page
            context.Response.Redirect("/");
            context.HandleResponse();

            return Task.CompletedTask;
        }

        private static Task OnRemoteFailure(RemoteFailureContext context)
        {
            // Handle authentication failures gracefully
            context.HandleResponse();

            // Check if the error is access_denied (user denied consent)
            if (context.Failure?.Message?.Contains("access_denied") == true)
            {
                // Redirect to home page with a message
                context.Response.Redirect("/?error=access_denied&message=" + Uri.EscapeDataString("Authorization was denied. You declined to grant access to the application."));
            }
            else
            {
                // For other errors, redirect to home with generic error
                var errorMessage = context.Failure?.Message ?? "An authentication error occurred";
                context.Response.Redirect("/?error=auth_failed&message=" + Uri.EscapeDataString(errorMessage));
            }

            return Task.CompletedTask;
        }

        private static Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedContext context, OIDCConfiguration oidcConfig)
        {
            // Load certificate from config (supports Base64 and file path)
            var certificate = LoadCertificateFromConfig(oidcConfig.ClientCertificate);
            
            if (certificate != null)
            {
                var clientAssertion = GenerateClientAssertion(certificate, oidcConfig.ClientId, oidcConfig.Authority);

                context.TokenEndpointRequest.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                context.TokenEndpointRequest.ClientAssertion = clientAssertion;
            }

            return Task.CompletedTask;
        }

        #endregion
    }
}
