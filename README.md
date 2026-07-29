# blapki

A small SCEP PKI server, written in Rust, that issues X.509 certificates to
Microsoft Intune-managed devices. It is comparable to SCEPman / Microsoft Cloud
PKI and to PacketFence's `pfpki`, but self-hosted and dependency-light: a single
static binary with a SQLite database by default.

## What it does

- Speaks SCEP over HTTP (RFC 8894): `GetCACaps`, `GetCACert`, and `PKIOperation`
  (enrolment and renewal).
- Validates the Intune dynamic SCEP challenge against the Intune API, or a static
  shared secret for testing and non-Intune clients.
- Answers OCSP (RFC 6960) and publishes a CRL for the certificates it issues.
- Stores state in SQLite by default; switch to Postgres or MySQL with a
  connection URL, no code change.
- Pure-Rust crypto (RustCrypto + rustls), no OpenSSL, so it builds to a small
  static musl binary.

CAs and SCEP profiles are defined in a config file. The database only holds
issued-certificate, transaction, and revocation state.

## Quick start

```sh
cp config.example.toml config.toml
cp .env.example .env         # set BLAPKI_TEST_CHALLENGE
cargo run
```

On first start, if a CA key file does not exist, a self-signed CA is generated
and written to the configured path (a convenience for development; provide your
own CA key in production). Then:

```sh
# Capabilities
curl "http://localhost:8080/scep/test?operation=GetCACaps"

# CA certificate (DER)
curl "http://localhost:8080/scep/test?operation=GetCACert" -o ca.der
openssl x509 -inform DER -in ca.der -noout -text
```

Enrol a device with the [sscep](https://github.com/certnanny/sscep) client
through the static-challenge `test` profile. sscep does not generate the key or
CSR, so create them with openssl first:

```sh
# 1. Device private key.
openssl genrsa -out device.key 2048

# 2. CSR carrying the SCEP challenge password. challengePassword must equal
#    BLAPKI_TEST_CHALLENGE (the "test" profile's secret). The subjectAltName is
#    optional; blapki copies it into the issued certificate.
cat > device.cnf <<'EOF'
[req]
prompt = no
distinguished_name = dn
attributes = attrs
req_extensions = exts
[dn]
CN = device-01
[attrs]
challengePassword = change-me
[exts]
subjectAltName = DNS:device-01.example.com
EOF
openssl req -new -key device.key -out device.csr -config device.cnf

# 3. Fetch the CA certificate, then enrol (writes device.crt).
sscep getca  -u http://localhost:8080/scep/test -c ca.crt
sscep enroll -u http://localhost:8080/scep/test \
  -c ca.crt -k device.key -r device.csr -l device.crt \
  -E aes256 -S sha256

# 4. Inspect the issued certificate.
openssl x509 -in device.crt -noout -subject -issuer -ext subjectAltName
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/scep/{profile}?operation=GetCACaps` | Advertised capabilities |
| GET | `/scep/{profile}?operation=GetCACert` | CA certificate (DER) |
| GET/POST | `/scep/{profile}` (`?operation=PKIOperation`) | Enrolment / renewal |
| POST | `/ocsp/{ca}` | OCSP request (DER body) |
| GET | `/ocsp/{ca}/{base64}` | OCSP request (base64 in path) |
| GET | `/crl/{ca}` | Current CRL (DER) |
| GET | `/health` | Liveness, lists CAs and profiles |

Windows and Intune append `/pkiclient.exe`; that path maps to the same handlers.

## Configuration

See [config.example.toml](config.example.toml). Secrets are never stored in the
file: fields ending in `_env` name an environment variable holding the secret.
Any value can also be overridden with a `BLAPKI_`-prefixed environment variable
(`__` separates nested keys, e.g. `BLAPKI_SERVER__LISTEN`).

### CA key material

Each `[[ca]]` gets its certificate and key from one of two sources:

- `key_file`: a PEM bundle (CERTIFICATE + private key block). If it is missing,
  a self-signed CA is generated and written there on first start.
- Inline PEM: `cert_pem` / `key_pem` hold the plain PEM
  (`-----BEGIN CERTIFICATE-----` / `-----BEGIN PRIVATE KEY-----`; use TOML
  triple-quoted strings for the multi-line value). The `cert_pem_env` /
  `key_pem_env` variants read the value from an environment variable instead, so
  you can inject the CA from a secret without a mounted file. A base64 blob of
  PEM or DER is also accepted. Provide both the cert and the key.

An encrypted PKCS#8 key is decrypted with the password in `key_password_env`.

### Database

Database backend is selected by the URL:

- `sqlite://blapki.db?mode=rwc` (default; `?mode=rwc` creates the file)
- `postgres://user:pass@host/db`
- `mysql://user:pass@host/db`

## Intune setup

For a profile with `challenge = "intune"`:

1. Register an app in Microsoft Entra ID and grant it the **Microsoft Intune API
   / SCEP challenge validation** and **Application.Read.All** application
   permissions (grant admin consent).
2. Put `tenant_id`, `client_id`, and a client-secret environment variable in the
   `[intune]` config section.
3. In Intune, create a SCEP certificate profile whose server URL points at
   `https://<host>/scep/intune`, with the trusted-root profile set to this CA's
   certificate.

On enrolment, blapki calls Intune to validate the request, issues the
certificate, and reports success or failure back to Intune.

## Development

```sh
cargo test --all       # crypto round-trip, HTTP enrolment, OCSP + CRL
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

The tests cover the full pipeline end-to-end: building and verifying signed SCEP
messages, decrypting the enveloped CSR, issuing a certificate, and the OCSP /
CRL revocation flow, with no external services required.

## Deployment

```sh
docker build -t blapki .
docker run -p 8080:8080 -v "$PWD/data:/data" -v "$PWD/config.toml:/app/config.toml:ro" blapki
```

The image runs as a non-root user. Mount a volume for the SQLite database and CA
key material, or point `database_url` at Postgres/MySQL and provide the CA key
via the configured path.

## License

MIT. Copyright BlaLabs.
