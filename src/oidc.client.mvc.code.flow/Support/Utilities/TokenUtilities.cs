using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace oidc.client.mvc.code.flow.Support.Utilities
{
    public static class TokenUtilities
    {
        #region statics.

        public static JwtSecurityToken? DecodeToken(string? jwt)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(jwt)) return null;

                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(jwt);

                return token;
            }
            catch
            {
                return null;
            }
        }
        public static string? EncodeToken(JwtSecurityToken? jwt)
        {
            return jwt?.RawHeader;
        }
        public static string? GetToken(HttpRequest httpRequest)
        {
            try
            {
                var jwtNative = httpRequest?.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(jwtNative)) return null;
                jwtNative = jwtNative.Replace("Bearer ", "");

                return jwtNative;
            }
            catch
            {
                return null;
            }
        }
        public static string GenerateToken(string privateKey = "PrivateKey",
                                           string name = "system.component",
                                           string email = "",
                                           string role = "system",
                                           string issuer = "self",
                                           string audience = "system",
                                           double expiresInMinutes = 60 * 24,
                                           IEnumerable<Claim>? customClaims = null)
        {
            // ...
            var now = DateTime.UtcNow;
            var subject = GenerateClaims(name, email, role, customClaims);
            var signingCredentials = GetSigningCredentials(privateKey);

            // ...
            var handler = new JwtSecurityTokenHandler();
            return handler.CreateEncodedJwt(new SecurityTokenDescriptor()
            {
                Subject = subject,
                Issuer = issuer,
                Audience = audience,
                IssuedAt = now,
                Expires = now.AddMinutes(expiresInMinutes),
                SigningCredentials = signingCredentials,
            });
        }

        public static string? GenerateToken(string? referenceJWT,
                                            string privateKey = "PrivateKey")
        {
            // ...
            var sourceToken = DecodeToken(referenceJWT);
            if (sourceToken == null) return null;

            // ...
            var subject = new ClaimsIdentity(sourceToken.Claims);
            var signingCredentials = GetSigningCredentials(privateKey);

            // ...
            var handler = new JwtSecurityTokenHandler();
            return handler.CreateEncodedJwt(new SecurityTokenDescriptor()
            {
                Subject = subject,
                Issuer = sourceToken.Issuer,
                IssuedAt = sourceToken.IssuedAt,
                Expires = sourceToken.ValidTo,
                SigningCredentials = signingCredentials,
            });
        }

        public static List<Claim>? GetClaims(string? jwt)
        {
            var token = DecodeToken(jwt);
            return token?.Claims?.ToList();
        }
        public static List<string>? GetClaimsSummary(string? jwt)
        {
            var token = DecodeToken(jwt);
            return token?.Claims?.ToList()?.Select(x => $"{x.Type} : {x.Value}")?.ToList();
        }
        public static Claim? GetClaim(string? jwt, string key)
        {
            var token = DecodeToken(jwt);
            return token?.Claims?.Where(x => x.Type == key)?.FirstOrDefault();
        }

        #endregion
        #region helpers.

        private static byte[] GetBytes(this string str)
        {
            var bytes = new byte[str.Length * sizeof(char)];
            Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }
        private static SigningCredentials GetSigningCredentials(string privateKey)
        {
            var symmetricKeyBytes = privateKey?.GetBytes();
            var symmetricKey = new SymmetricSecurityKey(symmetricKeyBytes);

            var signingCredentials = new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256Signature);

            return signingCredentials;
        }

        private static ClaimsIdentity GenerateClaims(string name = "system.component",
                                                     string email = "",
                                                     string role = "system",
                                                     IEnumerable<Claim>? customClaims = null)
        {
            var subject = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, name),
                new Claim(ClaimTypes.Email, email),
                new Claim(ClaimTypes.Role, role),
            ]);

            if (customClaims != null && customClaims.Any())
            {
                subject.AddClaims(customClaims);
            }

            return subject;
        }

        #endregion
    }
}
