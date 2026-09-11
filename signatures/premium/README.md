# Premium Signatures

This directory is a placeholder. Premium signature patterns are **not** bundled
in the open-source repository.

Premium intelligence includes:
- Social engineering patterns (authority impersonation, urgency manipulation, context manipulation)
- Business logic abuse (account takeover, refund fraud, employee safety, data exfiltration)
- Advanced evasion techniques
- Rapidly updated patterns based on emerging threats

## How to Access

Premium signatures are available via:
1. **Managed Backend (Model 2):** Included automatically when connected to the Agent Vardøger service.
2. **Subscription Feed (Model 1):** Set `VARDOGER_SIGNATURE_FEED_URL` to your subscription endpoint. Patterns are fetched, validated, and cached by the SignatureScanner.

## Self-Authored Signatures

You can create your own signatures following the format in `signatures/community/`.
If they detect real attacks, please consider contributing them back — see [CONTRIBUTING.md](../../CONTRIBUTING.md).
