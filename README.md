# XML-DSig

[wersja polska](README_PL.md)

Description
-
Library for generating XML Digital Signatures (XML-DSig) with support for XAdES elements and optional timestamps (TSA). It supports creating enveloped signatures for XML documents and includes helpers to load PKCS#12 certificates and prepare TLS configuration.

This library is a fork of [invopop/xmldsig](https://github.com/invopop/xmldsig) and has been adapted for integration with Poland's electronic invoicing system KSeF.

Supported algorithms and features
-
- RSA and ECDSA keys for signatures.
- Exclusive Canonicalization (Exclusive C14N) using `github.com/ucarion/c14n` for `SignedInfo` and `SignedProperties` where required.
- Generation of XAdES `QualifyingProperties` (e.g. `SigningTime`, `SigningCertificate`, optional `SignerRole`).
- Optional timestamping (TSA) via `WithTimestamp`.
- Load certificates from PKCS#12 files (`.p12`, `.pfx`) using `LoadCertificate`.
- Certificate helper methods: `Fingerprint()`, `NakedPEM()`, `PEM()`, `PrivateKey()`, `TLSAuthConfig()`.

Installation
-
Use the standard Go command:

```bash
go get github.com/geemark7/xmldsig
```

Quick usage
-
1) Load a PKCS#12 certificate and sign data:

```go
cert, err := xmldsig.LoadCertificate("./cert.p12", "password")
if err != nil {
	// handle error
}
sig, err := xmldsig.Sign(data,
	xmldsig.WithCertificate(cert),
	xmldsig.WithXAdES(&xmldsig.XAdESConfig{Role: xmldsig.XAdESSignerRole("signer")}),
	xmldsig.WithTimestamp(xmldsig.TimestampFreeTSA),
)
if err != nil {
	// handle error
}
// Attach `sig` to your main XML struct (field e.g. `xml:"ds:Signature,omitempty"`) and emit the document
```

KSeF client example
-
Example adapted from a KSeF client.

```go
// XML document structure that requires a signature
type AuthTokenRequest struct {
	XMLName           xml.Name `xml:"AuthTokenRequest"`
	XMLNS             string   `xml:"xmlns,attr"`
	Challenge         string   `xml:"Challenge"`
	ContextIdentifier struct {
		Nip string `xml:"Nip"`
	} `xml:"ContextIdentifier"`
	SubjectIdentifierType string             `xml:"SubjectIdentifierType"`
	Signature             *xmldsig.Signature `xml:"ds:Signature,omitempty"` // Add signature object!
}

// signXMLWithXAdESFromP12 creates an XAdES signature from a PKCS#12 file
func signXMLWithXAdESFromP12(authRequest *AuthTokenRequest, p12Path, pin string) ([]byte, error) {
	// Load certificate from PKCS#12
	cert, err := xmldsig.LoadCertificate(p12Path, pin)
	if err != nil {
		return nil, fmt.Errorf("loading certificate from P12: %w", err)
	}

	// XAdES configuration
	xades := &xmldsig.XAdESConfig{
		Role:        xmldsig.XAdESSignerRole(""),
		Description: "",
	}

	// Marshal the document to XML
	xmlBytes, err := xml.Marshal(authRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal xml: %w", err)
	}

	// Create XAdES signature
	signature, err := xmldsig.Sign(xmlBytes,
		xmldsig.WithCertificate(cert),
		xmldsig.WithXAdES(xades),
	)
	if err != nil {
		return nil, fmt.Errorf("create XAdES signature: %w", err)
	}

	// Attach signature to document
	authRequest.Signature = signature
	out, err := xml.Marshal(authRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal signed xml: %w", err)
	}

	return out, nil
}
```

Sign options
-
The library's `Sign` function accepts the following options:
- `WithCertificate(cert *Certificate)` — required to sign.
- `WithXAdES(config *XAdESConfig)` — creates XAdES `QualifyingProperties`.
- `WithTimestamp(url string)` — adds timestamping from a TSA (Time Stamping Authority).
- `WithNamespace(name, url string)` — include extra namespaces used during canonicalization.
- `WithDocID(id string)` — override the internal document ID.
- `WithCurrentTime(fn func() time.Time)` — set a custom signing time (useful for tests).

Certificates
-
- The library expects certificates in PKCS#12 format (`.p12`/`.pfx`).
- If you have certificates in PEM/X.509 format, convert them with OpenSSL. Example commands are described in the original upstream README.
- The order of certificates in the PKCS#12 bundle matters — the primary certificate should be first.

Technical notes
-
- Canonicalization: the library applies attribute ordering and duplicate-namespace removal helpers and uses `github.com/ucarion/c14n` for Exclusive C14N where required.
- ECDSA signatures are produced in R||S format as required by XML-DSig (not ASN.1 DER).
- Default algorithms: SHA-256 for digests and signatures.
- For compatibility with specific systems, check the transforms and reference identifiers in the implementation (`signature.go`).

License
-
This project is released under the Apache 2.0 license.


