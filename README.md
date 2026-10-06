# AniVora Security

AniVora Security is the reusable security foundation for the AniVora platform.

It is designed to provide common security capabilities for:

- AniVora Builder
- AniVora API
- AniVora Cloud
- AniVora Compute
- AniVora Cloud Phone
- AniVora VPN

CareerCraft remains a separate application and will use its own
application-specific security integration.

---

## Security capabilities

AniVora Security currently provides:

- Secure password hashing
- Password verification
- API-key generation
- API-key hashing
- Constant-time API-key comparison
- JWT authentication
- JWT expiration
- JWT issuer validation
- JWT audience validation
- JWT scopes
- User authorization
- Resource ownership checks
- Input validation
- AI prompt validation
- Request IDs
- Security headers
- Content Security Policy
- Host-header protection
- CORS configuration
- Rate limiting
- Security event logging
- Sensitive-data redaction
- Safe error handling

---

## Architecture

```text
                    Internet
                       |
                       v
                AniVora Security
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
 Authentication   Authorization   Rate Limiting
        |              |              |
        +--------------+--------------+
                       |
                       v
                AniVora Services
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
   AniVora API     Builder        Cloud Services
