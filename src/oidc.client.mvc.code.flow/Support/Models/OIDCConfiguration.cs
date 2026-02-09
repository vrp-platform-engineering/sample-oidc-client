namespace oidc.client.mvc.code.flow.Support.Models
{
    public class OIDCConfiguration
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        public string Authority { get; set; }

        public string CookieName { get; set; }
        public int? CookieExpiresInMinutes { get; set; }
        public int? AccessTokenExpiresInMinutes { get; set; }

        public string ResponseType { get; set; }
        public bool? JwtSecurityTokenMapInboundClaims { get; set; }
        public bool? RequireHttpsMetadata { get; set; }
        public bool? SaveTokens { get; set; }
        
        public List<string> Scopes { get; set; }
        public string RedirectUri { get; set; }
        public string PostLogoutRedirectUri { get; set; }

        public bool? SkipOIDCServerCertificateCheck { get; set; }

        public ClientCertificateConfiguration ClientCertificate { get; set; }
    }

    public class ClientCertificateConfiguration
    {
        public string CertificatePath { get; set; }
        public string CertificateBase64 { get; set; }
        public string CertificatePassword { get; set; }
    }
}
