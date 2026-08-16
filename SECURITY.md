# Security policy

## Supported version

Security fixes are made on the latest `main` revision. No long-term support branch is promised before a stable 1.0 release.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available. Do not open a public issue containing a subscription URL, token, cookie, password, HA1 value, private/public key material, `known_hosts`, raw device configuration, real IP topology, or authenticated URL.

Include only the minimum reproducible synthetic input, affected revision, expected/actual behavior, impact, and whether the issue can alter active configuration. Replace all sensitive values with `example.invalid`, RFC 5737 addresses, hashes, or explicit `REDACTED` markers.

## Security model

- All unexpected input or drift should become `HOLD`.
- A Candidate is not active configuration.
- Worker and router keys are independent per target.
- Receipts must not contain subscription credentials or converted YAML.
- The Web helper and SSH assets must be root-owned and not writable by the service user.
- Digest SHA-256 is the default; legacy MD5 is opt-in and suitable only for a trusted management network.

Security reports that require production secrets to reproduce will be rejected; create a synthetic fixture instead.
