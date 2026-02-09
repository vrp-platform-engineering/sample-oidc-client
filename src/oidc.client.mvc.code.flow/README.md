# VeriPark IDP Service - OIDC Integration Guide

> **For External Clients** | This guide helps third-party applications integrate with VeriPark's Identity Provider (IDP) Service using OpenID Connect (OIDC).

## Table of Contents

1. [Overview](#overview)
2. [OIDC Authorization Code Flow](#oidc-authorization-code-flow)
3. [Integration Prerequisites](#integration-prerequisites)
4. [Configuration Reference](#configuration-reference)
5. [Implementation Steps](#implementation-steps)
6. [Authentication Flows](#authentication-flows)
7. [Tokens & Claims](#tokens--claims)
8. [Certificate-Based Authentication](#certificate-based-authentication-optional)
9. [Troubleshooting](#troubleshooting)
10. [Reference Implementation (.NET)](#reference-implementation-net)

---

## Overview

VeriPark IDP Service is a fully compliant **OAuth 2.0 / OpenID Connect** Identity Provider. It supports:

- **Authorization Code Flow with PKCE** (required for all clients)
- **Refresh Token Flow** (for long-lived sessions)
- **Client-Initiated Logout** (coordinated logout across applications)

> **Important:** PKCE (Proof Key for Code Exchange) is **required** for all authorization requests. This provides enhanced security against authorization code interception attacks.

### Endpoints

| Endpoint | URL |
|----------|-----|
| Discovery Document | `{Authority}/.well-known/openid-configuration` |
| Authorization | `{Authority}/connect/authorize` |
| Token | `{Authority}/connect/token` |
| UserInfo | `{Authority}/connect/userinfo` |
| End Session (Logout) | `{Authority}/connect/endsession` |
| JWKS (Public Keys) | `{Authority}/.well-known/jwks.json` |

> **Note:** Replace `{Authority}` with the IDP base URL provided by VeriPark (e.g., `https://idp.yourbank.com`).

### Features Not Supported

The following OIDC/OAuth 2.0 features are **not available**:

| Feature | Status | Notes |
|---------|--------|-------|
| Implicit Flow | ❌ Not Supported | Use Authorization Code Flow with PKCE instead |
| Resource Owner Password (ROPC) | ❌ Not Supported | Direct username/password authentication not allowed |
| Client Credentials Flow | ❌ Not Supported | Machine-to-machine tokens not available |
| Token Encryption | ❌ Disabled | Access tokens are signed but not encrypted |
| Token Introspection | ❌ Not Available | Validate tokens using JWKS endpoint instead |

---

## OIDC Authorization Code Flow

```
┌─────────────────┐                              ┌──────────────────┐
│   Your Client   │                              │  VeriPark IDP    │
│   Application   │                              │     Service      │
└────────┬────────┘                              └────────┬─────────┘
         │                                                │
         │  1. Generate code_verifier (random string)     │
         │     code_challenge = SHA256(code_verifier)     │
         │                                                │
         │  2. Redirect user to /connect/authorize        │
         │  ─────────────────────────────────────────────>│
         │     ?client_id=...&redirect_uri=...            │
         │     &response_type=code&scope=openid...        │
         │     &code_challenge=...&code_challenge_method=S256
         │                                                │
         │                                    3. User logs in
         │                                    4. User grants consent (if required)
         │                                                │
         │  5. Redirect back with authorization code      │
         │  <─────────────────────────────────────────────│
         │     ?code=xyz123&state=...                     │
         │                                                │
         │  6. POST /connect/token                        │
         │  ─────────────────────────────────────────────>│
         │     grant_type=authorization_code              │
         │     code=xyz123&client_id=...&code_verifier=...│
         │                                                │
         │  7. Tokens returned                            │
         │  <─────────────────────────────────────────────│
         │     { access_token, id_token, refresh_token }  │
         │                                                │
         │  8. Call protected APIs with access_token      │
         │  ─────────────────────────────────────────────>│
         │                                                │
```

---

## Integration Prerequisites

Integration requires coordination between **your team** (Client) and **VeriPark team** (IDP).

### ✅ TASK: Customer Team Provides

| Item | Description | Example |
|------|-------------|---------|
| **Application Name** | Display name shown on consent screen | "MyBanking Mobile App" |
| **Redirect URIs** | Callback URLs after authentication | `https://your-app.com/signin-oidc` |
| **Post-Logout Redirect URIs** | URLs after logout | `https://your-app.com/signout-callback` |
| **Authentication Method** | Client Secret or Certificate | Client Secret |
| **Client Certificate** *(if using certificate auth)* | Generate certificate, share **public certificate (.cer)** with VeriPark | RSA 2048-bit minimum |

### ✅ TASK: VeriPark Team Provides

| Item | Description |
|------|-------------|
| **Authority URL** | IDP base URL (e.g., `https://idp.yourbank.com`) |
| **Client ID** | Unique identifier for your application |
| **Client Secret** | Shared secret (if using secret-based auth) |
| **Allowed Scopes** | List of scopes your client can request (see [Scopes](#available-scopes)) |

---

## Configuration Reference

Configure your OIDC client library with these parameters:

### Common Parameters (All Clients)

| Parameter | Value | Description |
|-----------|-------|-------------|
| `Authority` | Provided by VeriPark | IDP base URL |
| `ClientId` | Provided by VeriPark | Your application's identifier |
| `ResponseType` | `code` | Authorization Code Flow |
| `RedirectUri` | Your callback URL | Must match registered URI |
| `PostLogoutRedirectUri` | Your logout callback | Must match registered URI |
| `Scopes` | See below | Space-separated list |

### Client Authentication (Choose ONE)

**Option A: Client Secret** *(simpler setup)*

| Parameter | Value | Description |
|-----------|-------|-------------|
| `ClientSecret` | Provided by VeriPark | Shared secret for authentication |

**Option B: Client Certificate** *(enhanced security)*

| Parameter | Value | Description |
|-----------|-------|-------------|
| `ClientCertificate` | Your private key (.pfx/.p12) | Used to sign JWT client assertions |
| `CertificatePassword` | Certificate password | Password protecting the private key |

> **Note:** You must choose ONE authentication method. Certificate authentication is recommended for production environments requiring enhanced security.

### Available Scopes

VeriPark will provide the list of scopes allowed for your client. You can only request scopes that have been pre-configured for your Client ID.

| Scope | Claims Returned | Description |
|-------|-----------------|-------------|
| `openid` | `sub` (subject identifier) | **Required** - Enables OIDC |
| `profile` | `name`, `given_name`, `family_name` | User's name information |
| `email` | `email`, `email_verified` | User's email address |
| `roles` | `role` | User's assigned roles |
| `offline_access` | *(enables refresh tokens)* | Long-lived sessions |
| `member_id` | `member_id`, `pseudo_id` | Bank member/customer ID (custom) |

> **Note:** Request only the scopes you need. Requesting scopes not configured for your client will result in an error.

### Certificate Authentication Details

If using **Option B: Client Certificate** (see above), you must meet these additional requirements:

**Certificate Requirements:**
- **Key Type:** RSA (2048-bit minimum)
- **Format:** PFX/P12 (contains private key) for your application, CER (public key only) to share with VeriPark

**JWT Client Assertion Requirements:**

When authenticating with certificate, you must generate a JWT client assertion with these specific requirements:

| JWT Field | Value | Notes |
|-----------|-------|-------|
| **Header** | | |
| `alg` | `RS256` | RSA SHA-256 signing algorithm |
| `typ` | `client-authentication+jwt` | **Required** - Must be exactly this value |
| `kid` | Certificate thumbprint | Identifies which certificate signed the JWT |
| **Payload** | | |
| `iss` | Your Client ID | Issuer = your application |
| `sub` | Your Client ID | Subject = your application |
| `aud` | `{Authority}/` | **Must include trailing slash** |
| `jti` | Unique ID (GUID) | Prevents replay attacks |
| `iat` | Current timestamp | Issued at time |
| `exp` | Current + 5 minutes | Short expiration for security |
| `nbf` | Current - 5 minutes | Clock skew tolerance |

> **Important:** The `typ` header value `client-authentication+jwt` is required per OAuth 2.0 spec. Older JWT types like `JWT` will be rejected.

---

## Implementation Steps

### Step 1: Configure OIDC Client

Use your platform's OIDC library:

| Platform | Recommended Library |
|----------|---------------------|
| .NET | `Microsoft.AspNetCore.Authentication.OpenIdConnect` |
| Java | Spring Security OAuth2 / Keycloak Adapter |
| Node.js | `openid-client` / `passport-openidconnect` |
| Python | `Authlib` / `python-jose` |
| Mobile (iOS/Android) | AppAuth |

### Step 2: Initiate Login

**Generate PKCE Values First:**
1. Generate a random `code_verifier` (43-128 characters, URL-safe)
2. Compute `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Store `code_verifier` securely (you'll need it for token exchange)

**Redirect user to authorization endpoint:**

```
GET {Authority}/connect/authorize
    ?client_id={ClientId}
    &redirect_uri={RedirectUri}
    &response_type=code
    &scope=openid profile email
    &state={RandomState}
    &nonce={RandomNonce}
    &code_challenge={CodeChallenge}
    &code_challenge_method=S256
```

| Parameter | Description |
|-----------|-------------|
| `client_id` | Your Client ID (from VeriPark) |
| `redirect_uri` | Your callback URL (must be pre-registered) |
| `response_type` | Always `code` for Authorization Code Flow |
| `scope` | Space-separated scopes (from allowed scopes) |
| `state` | Random string for CSRF protection |
| `nonce` | Random string to prevent replay attacks |
| `code_challenge` | **Required** - SHA256 hash of code_verifier, Base64URL encoded |
| `code_challenge_method` | **Required** - Always `S256` |

### Step 3: Handle Callback

Your redirect URI receives:
- `code` - Authorization code (exchange for tokens)
- `state` - Must match original state for CSRF protection

### Step 4: Exchange Code for Tokens

```http
POST {Authority}/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={AuthorizationCode}
&redirect_uri={RedirectUri}
&client_id={ClientId}
&client_secret={ClientSecret}
&code_verifier={CodeVerifier}
```

> **Note:** `code_verifier` is the original random string generated in Step 2. The IDP verifies that `SHA256(code_verifier)` matches the `code_challenge` sent during authorization.

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "8xLOxBtZp8..."
}
```

### Step 5: Store and Use Tokens

- **Access Token**: Include in API requests as `Authorization: Bearer {token}`
- **ID Token**: Contains user identity claims (verify signature using JWKS endpoint)
- **Refresh Token**: Use to get new access tokens without user re-authentication

---

## Authentication Flows

### Login with Consent

1. User clicks "Login" in your application
2. Redirect to VeriPark IDP authorization endpoint
3. User authenticates (may include multi-step: password, OTP, security questions)
4. **Consent screen** displayed (based on consent type configured by VeriPark)
5. User approves → Redirected back to your application with authorization code

### Token Refresh

When access token expires, use refresh token to get new tokens:

```http
POST {Authority}/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token={RefreshToken}
&client_id={ClientId}
&client_secret={ClientSecret}
```

### Logout (Client-Initiated)

To log the user out and redirect them back to your application:

```
GET {Authority}/connect/endsession
    ?id_token_hint={IdToken}
    &post_logout_redirect_uri={PostLogoutRedirectUri}
    &state={RandomState}
```

| Parameter | Description |
|-----------|-------------|
| `id_token_hint` | The ID token received during login |
| `post_logout_redirect_uri` | Where to redirect after logout (must be pre-registered) |
| `state` | Random string for identifying the logout request |

---

## Tokens & Claims

### ID Token Claims

| Claim | Description | Example |
|-------|-------------|---------|
| `sub` | Subject identifier (user ID) | `"user_12345"` |
| `name` | Full name | `"John Doe"` |
| `email` | Email address | `"john@example.com"` |
| `role` | User roles (array or string) | `["Member", "Admin"]` |
| `iss` | Issuer (IDP URL) | `"https://idp.bank.com/"` |
| `aud` | Audience (your Client ID) | `"your-client-id"` |
| `exp` | Expiration time (Unix timestamp) | `1738934400` |
| `iat` | Issued at (Unix timestamp) | `1738932600` |

### Custom Claims (if configured)

| Claim | Description |
|-------|-------------|
| `member_id` | Bank member/customer identifier |

### Token Validation

Always validate tokens before trusting claims:

1. **Signature**: Verify using IDP's public keys from `{Authority}/.well-known/jwks.json`
2. **Issuer (`iss`)**: Must match the Authority URL
3. **Audience (`aud`)**: Must match your Client ID
4. **Expiration (`exp`)**: Token must not be expired
5. **Nonce**: Must match the nonce sent in authorization request (for ID tokens)

---

## Certificate-Based Authentication (Optional)

For enhanced security, use certificate-based client authentication instead of client secrets.

### ✅ TASK: Customer Team

1. **Generate RSA key pair** (2048-bit minimum, 4096-bit recommended)
2. **Create certificate** (self-signed or CA-signed)
3. **Share public certificate (.cer)** with VeriPark
4. **Keep private key secure** (never share the private key)

### ✅ TASK: VeriPark Team

1. Register your public certificate for your Client ID
2. Configure client for `private_key_jwt` authentication

### Implementation

Instead of `client_secret`, generate a JWT client assertion signed with your private key:

```http
POST {Authority}/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={AuthorizationCode}
&redirect_uri={RedirectUri}
&client_id={ClientId}
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion={SignedJWT}
```

**JWT Client Assertion Structure:**
```json
{
  "header": {
    "alg": "RS256",
    "typ": "client-authentication+jwt",
    "kid": "{CertificateThumbprint}"
  },
  "payload": {
    "iss": "{ClientId}",
    "sub": "{ClientId}",
    "aud": "{Authority}/",
    "jti": "{UniqueId}",
    "exp": "{ExpirationTimestamp}",
    "iat": "{IssuedAtTimestamp}"
  }
}
```

---

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_client` | Client ID or secret mismatch | Verify credentials with VeriPark |
| `invalid_redirect_uri` | Redirect URI not registered | Confirm exact URI is registered with VeriPark |
| `access_denied` | User denied consent | User must approve on consent screen |
| `invalid_grant` | Authorization code expired/reused | Codes are single-use and short-lived; retry login |
| `invalid_scope` | Requested scope not allowed | Request only scopes configured for your client |

### SSL/TLS Certificate Errors

- Ensure your environment trusts the IDP's SSL certificate
- In production, always validate certificates

### Token Signature Validation Fails

- Fetch latest public keys from `{Authority}/.well-known/jwks.json`
- Ensure clock synchronization (NTP) for `exp`/`iat` validation
- Check issuer URL matches exactly (watch for trailing slashes)

---

## Reference Implementation (.NET)

This repository contains a working .NET 8 reference implementation demonstrating:

- Authorization Code Flow with `Microsoft.AspNetCore.Authentication.OpenIdConnect`
- Cookie-based session management
- Token refresh handling
- Logout flow

### Key Files

| File | Purpose |
|------|---------|
| `Startup.cs` | Application setup, authentication middleware |
| `Support/IOC/SecurityIOCHelpers.cs` | OIDC configuration and event handlers |
| `appsettings.json` | Configuration example |
| `Controllers/HomeController.cs` | Token display and refresh actions |

### Running the Sample

1. Update `appsettings.json` with configuration from VeriPark
2. Run: `dotnet run`
3. Navigate to: `https://localhost:9000`

---

## Support

For integration support, contact your VeriPark representative.

---

*Last Updated: February 2026*
