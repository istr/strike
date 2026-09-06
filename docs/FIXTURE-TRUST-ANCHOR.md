# The fixture trust anchors

Every TLS trust anchor in this tree that exists only so a parser has something
to parse -- unit-test fixtures, the golden lane, documentation examples -- is
one of the three certificates recorded here, and every deliberately invalid
anchor is one of the two blobs recorded below them. They are reused
everywhere rather than generated per fixture.

They are checked in, and that is a deliberate boundary against
[ADR-018](ADR-018-ephemeral-test-material.md) rather than an exception to it:
see [ADR-056](ADR-056-tls-trust-anchor-as-inline-certificate.md) D8 and the
amendment note at the top of ADR-018. None of this material is a credential.
It is never presented, never validated against a live peer, and holds no
authority anywhere. The private key is not in this repository.

## The key

All five artifacts derive from one key: the P-256 key that
[RFC 9500](https://www.rfc-editor.org/rfc/rfc9500.txt) section 2.3 publishes
under the name `testECCP256`. RFC 9500 exists so that publicly known test keys
can be recognised as such, in the same spirit as the EICAR file; that
recognisability is the reason this key was chosen over a freshly generated
one.

The key itself is not recorded here. It is fetched from the RFC when the
material is regenerated, and identified by two digests that are independent of
PEM formatting:

- SubjectPublicKeyInfo DER, SHA-256:
  `b2b04340cfaee616ec9c2c62d261b208e54bb197498df52e8cadede23ac0ba5e`
- SEC1 private key DER, SHA-256:
  `152abe484b6f0aa434d0127c2cdc3fba48b95384a6e0f45704598c183fc79397`

RFC 9500 is Copyright (c) 2023 IETF Trust and the persons identified as the
document authors. Code Components extracted from it are licensed under the
Revised BSD License as described in section 4.e of the IETF Trust Legal
Provisions (https://trustee.ietf.org/license-info) and are provided without
warranty as described in that license.

## 1. The anchor -- self-signed, CA:TRUE

The trust anchor every valid fixture declares. Under `mode: rootca` it is
installed as the sole root; under `mode: leaf` it would be compared byte for
byte, though no fixture does that with this one.

```
MIIBuzCCAWGgAwIBAgIBATAKBggqhkjOPQQDAjBEMR0wGwYDVQQKDBRzdHJpa2UgdGVzdCBtYXRlcmlhbDEjMCEGA1UEAwwac3RyaWtlIGZpeHR1cmUgdGVzdCBhbmNob3IwIBcNMjYwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEQxHTAbBgNVBAoMFHN0cmlrZSB0ZXN0IG1hdGVyaWFsMSMwIQYDVQQDDBpzdHJpa2UgZml4dHVyZSB0ZXN0IGFuY2hvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyjdERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36QpCpJQnKjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRbcKeYF/ef9jfS9+PcRGwhCde71DAKBggqhkjOPQQDAgNIADBFAiEAgS0Tvd1/A38U+EpMiaA1GtTjXCX11rqbLgUQf5iRhhgCIDnuZnbVCpcQjNQLMsrhhzlFRTlAWOVNlS0apM4uHD/E
```

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=strike test material, CN=strike fixture test anchor
        Validity
            Not Before: Jan  1 00:00:00 2026 GMT
            Not After : Dec 31 23:59:59 9999 GMT
        Subject: O=strike test material, CN=strike fixture test anchor
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:42:25:48:f8:8f:b7:82:ff:b5:ec:a3:74:44:52:
                    c7:2a:1e:55:8f:bd:6f:73:be:5e:48:e9:32:32:cc:
                    45:c5:b1:6c:4c:d1:0c:4c:b8:d5:b8:a1:71:39:e9:
                    48:82:c8:99:25:72:99:34:25:f4:14:19:ab:7e:90:
                    a4:2a:49:42:72
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                5B:70:A7:98:17:F7:9F:F6:37:D2:F7:E3:DC:44:6C:21:09:D7:BB:D4
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:81:2d:13:bd:dd:7f:03:7f:14:f8:4a:4c:89:
        a0:35:1a:d4:e3:5c:25:f5:d6:ba:9b:2e:05:10:7f:98:91:86:
        18:02:20:39:ee:66:76:d5:0a:97:10:8c:d4:0b:32:ca:e1:87:
        39:45:45:39:40:58:e5:4d:95:2d:1a:a4:ce:2e:1c:3f:c4
```

## 2. The intermediate -- issued by the anchor, CA:TRUE

Its issuer and subject differ, so `mode: rootca` rejects it at validate time
per ADR-056 D4. Because it carries the same key as its issuer, its signature
does verify under its own key; the distinguished-name comparison is what
rejects it. The clause about a signature that does not verify under its own
key is exercised with ephemeral material in the unit tests, where it belongs.

```
MIIB4TCCAYigAwIBAgIBAjAKBggqhkjOPQQDAjBEMR0wGwYDVQQKDBRzdHJpa2UgdGVzdCBtYXRlcmlhbDEjMCEGA1UEAwwac3RyaWtlIGZpeHR1cmUgdGVzdCBhbmNob3IwIBcNMjYwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEoxHTAbBgNVBAoMFHN0cmlrZSB0ZXN0IG1hdGVyaWFsMSkwJwYDVQQDDCBzdHJpa2UgZml4dHVyZSB0ZXN0IGludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyjdERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36QpCpJQnKjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRbcKeYF/ef9jfS9+PcRGwhCde71DAfBgNVHSMEGDAWgBRbcKeYF/ef9jfS9+PcRGwhCde71DAKBggqhkjOPQQDAgNHADBEAiAKf+eovDFTS4j5Z/RHvCO/H4cPwuQGKGx9nbomTIjGfAIgLd+pZe9qC6JGrnG1nWFM26Eak3Zt/QAaOLbhNV/mip4=
```

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=strike test material, CN=strike fixture test anchor
        Validity
            Not Before: Jan  1 00:00:00 2026 GMT
            Not After : Dec 31 23:59:59 9999 GMT
        Subject: O=strike test material, CN=strike fixture test intermediate
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:42:25:48:f8:8f:b7:82:ff:b5:ec:a3:74:44:52:
                    c7:2a:1e:55:8f:bd:6f:73:be:5e:48:e9:32:32:cc:
                    45:c5:b1:6c:4c:d1:0c:4c:b8:d5:b8:a1:71:39:e9:
                    48:82:c8:99:25:72:99:34:25:f4:14:19:ab:7e:90:
                    a4:2a:49:42:72
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                5B:70:A7:98:17:F7:9F:F6:37:D2:F7:E3:DC:44:6C:21:09:D7:BB:D4
            X509v3 Authority Key Identifier: 
                5B:70:A7:98:17:F7:9F:F6:37:D2:F7:E3:DC:44:6C:21:09:D7:BB:D4
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:0a:7f:e7:a8:bc:31:53:4b:88:f9:67:f4:47:bc:
        23:bf:1f:87:0f:c2:e4:06:28:6c:7d:9d:ba:26:4c:88:c6:7c:
        02:20:2d:df:a9:65:ef:6a:0b:a2:46:ae:71:b5:9d:61:4c:db:
        a1:1a:93:76:6d:fd:00:1a:38:b6:e1:35:5f:e6:8a:9e
```

## 3. The leaf -- self-signed, CA:FALSE

Two roles. Under `mode: rootca` it is rejected on its basic constraints. Under
`mode: leaf` it is the positive fixture: an exact DER comparison in
`VerifyPeerCertificate`, never entering a root pool (ADR-056 D5). Its
subjectAltName names `fixture.invalid`, a name reserved by RFC 2606 that can
never resolve.

```
MIIB5DCCAYugAwIBAgIBAzAKBggqhkjOPQQDAjBCMR0wGwYDVQQKDBRzdHJpa2UgdGVzdCBtYXRlcmlhbDEhMB8GA1UEAwwYc3RyaWtlIGZpeHR1cmUgdGVzdCBsZWFmMCAXDTI2MDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjBCMR0wGwYDVQQKDBRzdHJpa2UgdGVzdCBtYXRlcmlhbDEhMB8GA1UEAwwYc3RyaWtlIGZpeHR1cmUgdGVzdCBsZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjVuKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcqNwMG4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFtwp5gX95/2N9L349xEbCEJ17vUMBoGA1UdEQQTMBGCD2ZpeHR1cmUuaW52YWxpZDAKBggqhkjOPQQDAgNHADBEAiBBt3rXj14WewBTb0EALe2HkJPmF2mJQe7pLJB3w1Dj0QIgeleJrHvu/0MwPMDzilfvebJg1gVTBfCBIxdC6tWyYtg=
```

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 3 (0x3)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=strike test material, CN=strike fixture test leaf
        Validity
            Not Before: Jan  1 00:00:00 2026 GMT
            Not After : Dec 31 23:59:59 9999 GMT
        Subject: O=strike test material, CN=strike fixture test leaf
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:42:25:48:f8:8f:b7:82:ff:b5:ec:a3:74:44:52:
                    c7:2a:1e:55:8f:bd:6f:73:be:5e:48:e9:32:32:cc:
                    45:c5:b1:6c:4c:d1:0c:4c:b8:d5:b8:a1:71:39:e9:
                    48:82:c8:99:25:72:99:34:25:f4:14:19:ab:7e:90:
                    a4:2a:49:42:72
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Key Identifier: 
                5B:70:A7:98:17:F7:9F:F6:37:D2:F7:E3:DC:44:6C:21:09:D7:BB:D4
            X509v3 Subject Alternative Name: 
                DNS:fixture.invalid
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:41:b7:7a:d7:8f:5e:16:7b:00:53:6f:41:00:2d:
        ed:87:90:93:e6:17:69:89:41:ee:e9:2c:90:77:c3:50:e3:d1:
        02:20:7a:57:89:ac:7b:ee:ff:43:30:3c:c0:f3:8a:57:ef:79:
        b2:60:d6:05:53:05:f0:81:23:17:42:ea:d5:b2:62:d8
```

## 4. Valid base64, not a certificate

The first 400 characters of artifact 1. 400 is a multiple of 4, so the value
satisfies `primitive.#Base64` and reaches the DER parse, which rejects the
truncated SEQUENCE.

```
MIIBuzCCAWGgAwIBAgIBATAKBggqhkjOPQQDAjBEMR0wGwYDVQQKDBRzdHJpa2UgdGVzdCBtYXRlcmlhbDEjMCEGA1UEAwwac3RyaWtlIGZpeHR1cmUgdGVzdCBhbmNob3IwIBcNMjYwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEQxHTAbBgNVBAoMFHN0cmlrZSB0ZXN0IG1hdGVyaWFsMSMwIQYDVQQDDBpzdHJpa2UgZml4dHVyZSB0ZXN0IGFuY2hvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyjdERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36QpCpJQnKjQjBAMA8G
```

## 5. Not base64

Artifact 1 with its final two characters replaced by `-` and `_`, the
base64url alphabet. `primitive.#Base64` rejects it at CUE validation, before
any Go code sees the value.

```
MIIBuzCCAWGgAwIBAgIBATAKBggqhkjOPQQDAjBEMR0wGwYDVQQKDBRzdHJpa2UgdGVzdCBtYXRlcmlhbDEjMCEGA1UEAwwac3RyaWtlIGZpeHR1cmUgdGVzdCBhbmNob3IwIBcNMjYwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEQxHTAbBgNVBAoMFHN0cmlrZSB0ZXN0IG1hdGVyaWFsMSMwIQYDVQQDDBpzdHJpa2UgZml4dHVyZSB0ZXN0IGFuY2hvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyjdERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36QpCpJQnKjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRbcKeYF/ef9jfS9+PcRGwhCde71DAKBggqhkjOPQQDAgNIADBFAiEAgS0Tvd1/A38U+EpMiaA1GtTjXCX11rqbLgUQf5iRhhgCIDnuZnbVCpcQjNQLMsrhhzlFRTlAWOVNlS0apM4uHD-_
```

## Regenerating

The bytes above are one-time. ECDSA signing draws randomness, so regenerating
from the same key with the same parameters produces different certificates.
Regeneration is therefore a deliberate act that replaces the material
everywhere it appears, not a routine step.

Fetch `https://www.rfc-editor.org/rfc/rfc9500.txt`, extract the
`-----BEGIN EC PRIVATE KEY-----` block that section 2.3 gives as the encoded
form of `testECCP256`, and check it against the two digests above. Then, with
`NB=20260101000000Z` and `NA=99991231235959Z`:

```sh
openssl req -new -key testECCP256.pem \
  -subj "/O=strike test material/CN=strike fixture test anchor" -out r1.csr
openssl x509 -req -in r1.csr -signkey testECCP256.pem -set_serial 1 \
  -not_before $NB -not_after $NA -extfile ca.cnf -out anchor.crt

openssl req -new -key testECCP256.pem \
  -subj "/O=strike test material/CN=strike fixture test intermediate" -out r2.csr
openssl x509 -req -in r2.csr -CA anchor.crt -CAkey testECCP256.pem -set_serial 2 \
  -not_before $NB -not_after $NA -extfile int.cnf -out intermediate.crt

openssl req -new -key testECCP256.pem \
  -subj "/O=strike test material/CN=strike fixture test leaf" -out r3.csr
openssl x509 -req -in r3.csr -signkey testECCP256.pem -set_serial 3 \
  -not_before $NB -not_after $NA -extfile leaf.cnf -out leaf.crt
```

with the extension files:

```
# ca.cnf
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

# int.cnf
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

# leaf.cnf
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
subjectAltName = DNS:fixture.invalid
```

`99991231235959Z` is the GeneralizedTime RFC 5280 section 4.1.2.5 assigns to a
certificate with no well-defined expiration date, so the fixture set has no
expiry to manage. The base64 form is unwrapped:
`openssl x509 -in anchor.crt -outform DER | base64 -w0`.

Emit artifacts 4 and 5 from artifact 1:

```sh
A=$(openssl x509 -in anchor.crt -outform DER | base64 -w0)
printf '%s\n' "$(printf '%s' "$A" | cut -c1-400)"
printf '%s\n' "${A%??}-_"
```

The private key, the CSRs, and the extension files are scratch. None of them
belongs in this repository.
