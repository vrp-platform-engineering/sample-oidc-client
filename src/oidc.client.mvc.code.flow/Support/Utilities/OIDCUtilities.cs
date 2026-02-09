using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using oidc.client.mvc.code.flow.Support.IOC;

namespace oidc.client.mvc.code.flow.Support.Utilities
{
    public static class OIDCUtilities
    {
        #region statics.

        public static async Task<object> RefreshToken(HttpContext httpContext,
                                                      string authority,
                                                      string clientId,
                                                      string clientSecret,
                                                      X509Certificate2? certificate,
                                                      string refreshToken,
                                                      bool skipCertificateValidation = false)
        {
            // Prepare refresh token request
            var tokenEndpoint = $"{authority}/connect/token";
            var requestData = new List<KeyValuePair<string, string>>
                {
                    new("grant_type", "refresh_token"),
                    new("refresh_token", refreshToken),
                    new("client_id", clientId),
                };

            if (!string.IsNullOrWhiteSpace(clientSecret))
            {
                requestData.Add(new("client_secret", clientSecret));
            }
            else if (certificate != null)
            {
                // Generate client assertion for this request
                var clientAssertion = SecurityIOCHelpers.GenerateClientAssertion(certificate, clientId, authority);

                requestData.Add(new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
                requestData.Add(new("client_assertion", clientAssertion));
            }

            // Create HttpClient with certificate validation bypass if needed
            HttpClient httpClient;
            if (skipCertificateValidation)
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };
                httpClient = new HttpClient(handler);
            }
            else
            {
                httpClient = new HttpClient();
            }

            using (httpClient)
            {
                var requestContent = new FormUrlEncodedContent(requestData);

                var response = await httpClient.PostAsync(tokenEndpoint, requestContent);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);

                    var newAccessToken = tokenResponse.TryGetProperty("access_token", out var accessToken) ? accessToken.GetString() : null;
                    var newIdToken = tokenResponse.TryGetProperty("id_token", out var idToken) ? idToken.GetString() : null;
                    var newRefreshToken = tokenResponse.TryGetProperty("refresh_token", out var newRefresh) ? newRefresh.GetString() : refreshToken; // Keep old if no new one
                    var expiresIn = tokenResponse.TryGetProperty("expires_in", out var expires) ? expires.GetInt32() : 3600;

                    // Update tokens in authentication properties
                    var authenticateResult = await httpContext.AuthenticateAsync();
                    if (authenticateResult.Succeeded && authenticateResult.Properties != null)
                    {
                        // Update tokens
                        authenticateResult.Properties.UpdateTokenValue("access_token", newAccessToken);
                        if (!string.IsNullOrEmpty(newIdToken))
                        {
                            authenticateResult.Properties.UpdateTokenValue("id_token", newIdToken);
                        }
                        authenticateResult.Properties.UpdateTokenValue("refresh_token", newRefreshToken);

                        // Update expiration
                        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
                        authenticateResult.Properties.UpdateTokenValue("expires_at", expiresAt.ToString("o"));

                        // Re-sign in with updated tokens
                        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                                    authenticateResult.Principal,
                                                    authenticateResult.Properties);
                    }

                    return new
                    {
                        success = true,
                        access_token = newAccessToken,
                        id_token = newIdToken,
                        refresh_token = newRefreshToken,
                    };
                }
                else
                {
                    return new
                    {
                        success = false,
                        error = "refresh_failed",
                        status_code = (int)response.StatusCode,
                        response = responseContent,
                        message = "Token refresh failed. You may need to login again."
                    };
                }
            }
        }

        #endregion
    }
}
