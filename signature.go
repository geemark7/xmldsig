package xmldsig

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/gobl/uuid"
	"github.com/ucarion/c14n"
)

// Namespaces
const (
	NamespaceXAdES = "http://uri.etsi.org/01903/v1.3.2#"
	NamespaceDSig  = "http://www.w3.org/2000/09/xmldsig#"
)

// Namespace names (short)
const (
	XMLNS = "xmlns"
	XAdES = "xades"
	DSig  = "ds"
)

// Algorithms
const (
	AlgEncSHA256     = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgEncSHA512     = "http://www.w3.org/2001/04/xmlenc#sha512"
	AlgDSigSHA1      = "http://www.w3.org/2000/09/xmldsig#sha1"
	AlgDSigRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	AlgDSigRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

// ISO8601 contains the time format used for signing times
// (based on https://en.wikipedia.org/wiki/ISO_8601)
const ISO8601 = "2006-01-02T15:04:05-07:00"

// Signature contains the complete signature to be added
// to the document.
type Signature struct {
	DSigNamespace string   `xml:"xmlns:ds,attr,omitempty"`
	ID            string   `xml:"Id,attr"`
	XMLName       xml.Name `xml:"ds:Signature"`

	SignedInfo *SignedInfo `xml:"ds:SignedInfo"`
	Value      *Value      `xml:"ds:SignatureValue"`
	KeyInfo    *KeyInfo    `xml:"ds:KeyInfo"`
	Object     *Object     `xml:"ds:Object,omitempty"`

	doc         []byte   `xml:"-"`
	opts        *options `xml:"-"`
	referenceID string   `xml:"-"` // reference ID to main content
}

// SignedInfo contains the info that will be signed by
// the certificate.
type SignedInfo struct {
	XMLName xml.Name `xml:"ds:SignedInfo"`
	ID      string   `xml:"Id,attr,omitempty"`

	CanonicalizationMethod *AlgorithmMethod `xml:"ds:CanonicalizationMethod"`
	SignatureMethod        *AlgorithmMethod `xml:"ds:SignatureMethod"`
	Reference              []*Reference     `xml:"ds:Reference"`
}

// Reference contains ...
type Reference struct {
	ID   string `xml:"Id,attr,omitempty"`
	Type string `xml:"Type,attr,omitempty"`
	URI  string `xml:"URI,attr"`

	Transforms   *Transforms      `xml:"ds:Transforms,omitempty"`
	DigestMethod *AlgorithmMethod `xml:"ds:DigestMethod"`
	DigestValue  string           `xml:"ds:DigestValue"`
}

// Transforms contains ...
type Transforms struct {
	Transform []*Transform `xml:"ds:Transform"`
}

// Transform contains transformation algorithm and optional XPath
type Transform struct {
	Algorithm string `xml:"Algorithm,attr"`
	XPath     string `xml:"ds:XPath,omitempty"`
}

// Value contains ...
type Value struct {
	ID    string `xml:"Id,attr"`
	Value string `xml:",chardata"`
}

// KeyInfo contains ...
type KeyInfo struct {
	XMLName xml.Name `xml:"ds:KeyInfo"`
	ID      string   `xml:"Id,attr"`

	X509Data *X509Data `xml:"ds:X509Data,omitempty"`
	KeyValue *KeyValue `xml:"ds:KeyValue,omitempty"`
}

// X509Data contains ...
type X509Data struct {
	X509Certificate []string `xml:"ds:X509Certificate"`
}

// KeyValue contains ...
type KeyValue struct {
	Modulus  string `xml:"ds:RSAKeyValue>ds:Modulus"`
	Exponent string `xml:"ds:RSAKeyValue>ds:Exponent"`
}

// Object contains ...
type Object struct {
	QualifyingProperties *QualifyingProperties `xml:"xades:QualifyingProperties"`
}

// QualifyingProperties the funny XaDES signature confirmation policy data. This is the only place the
// `xades` namespace is required, so we can add it just here.
type QualifyingProperties struct {
	XAdESNamespace string `xml:"xmlns:xades,attr,omitempty"`
	ID             string `xml:"Id,attr,omitempty"`
	Target         string `xml:"Target,attr"`

	SignedProperties   *SignedProperties   `xml:"xades:SignedProperties"`
	UnsignedProperties *UnsignedProperties `xml:"xades:UnsignedProperties,omitempty"`
}

// SignedProperties contains ...
type SignedProperties struct {
	XMLName xml.Name `xml:"xades:SignedProperties"`
	ID      string   `xml:"Id,attr"`

	SignatureProperties  *SignedSignatureProperties `xml:"xades:SignedSignatureProperties"`
	DataObjectProperties *DataObjectFormat          `xml:"xades:SignedDataObjectProperties>xades:DataObjectFormat,omitempty"`
}

// SignedSignatureProperties contains ...
type SignedSignatureProperties struct {
	SigningTime        string              `xml:"xades:SigningTime"`
	SigningCertificate *SigningCertificate `xml:"xades:SigningCertificate"`
	PolicyIdentifier   *PolicyIdentifier   `xml:"xades:SignaturePolicyIdentifier"`
	SignerRole         *SignerRole         `xml:"xades:SignerRole,omitempty"`
}

// SigningCertificate contains ...
type SigningCertificate struct {
	CertDigest   *Digest       `xml:"xades:Cert>xades:CertDigest"`
	IssuerSerial *IssuerSerial `xml:"xades:Cert>xades:IssuerSerial"`
}

// Digest contains ...
type Digest struct {
	Method *AlgorithmMethod `xml:"ds:DigestMethod"`
	Value  string           `xml:"ds:DigestValue"`
}

// AlgorithmMethod contains ...
type AlgorithmMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// IssuerSerial contains ...
type IssuerSerial struct {
	IssuerName   string `xml:"ds:X509IssuerName"`
	SerialNumber string `xml:"ds:X509SerialNumber"`
}

// PolicyIdentifier contains ...
type PolicyIdentifier struct {
	SigPolicyID      *SigPolicyID `xml:"xades:SignaturePolicyId>xades:SigPolicyId,omitempty"`
	SigPolicyHash    *Digest      `xml:"xades:SignaturePolicyId>xades:SigPolicyHash,omitempty"`
	SigPolicyImplied *struct{}    `xml:"xades:SignaturePolicyImplied,omitempty"`
}

// SigPolicyID contains ...
type SigPolicyID struct {
	Identifier  string `xml:"xades:Identifier"`
	Description string `xml:"xades:Description"`
}

// SignerRole contains ...
type SignerRole struct {
	ClaimedRoles *Roles `xml:"xades:ClaimedRoles"`
}

// Roles contains ...
type Roles struct {
	ClaimedRole []string `xml:"xades:ClaimedRole"`
}

// DataObjectFormat contains ...
type DataObjectFormat struct {
	ObjectReference string `xml:"ObjectReference,attr"`

	Description      string            `xml:"xades:Description"`
	ObjectIdentifier *ObjectIdentifier `xml:"xades:ObjectIdentifier"`
	MimeType         string            `xml:"xades:MimeType"`
	Encoding         string            `xml:"xades:Encoding"` // normally empty
}

// ObjectIdentifier holds and identifier
type ObjectIdentifier struct {
	Identifier  *Identifier `xml:"xades:Identifier"`
	Description string      `xml:"xades:Description"`
}

// Identifier contains ...
type Identifier struct {
	Qualifier string `xml:"Qualifier,attr"`
	Value     string `xml:",chardata"`
}

const (
	signatureIDFormat               = "Signature-%s"
	signatureRootIDFormat           = "Signature-%s" // Changed: removed -Signature suffix (compatible with mObywatel)
	sigPropertiesIDFormat           = "xades-%s"     // Changed: use xades- prefix (compatible with mObywatel)
	sigQualifyingPropertiesIDFormat = "QualifyingProps-%s"
	referenceIDFormat               = "Reference-%s"
	certificateIDFormat             = "Certificate-%s"
)

func newSignature(data []byte, opts ...Option) (*Signature, error) {
	o := &options{
		docID:      uuid.V1().String(),
		namespaces: make(Namespaces),
		timeNow:    currentTime,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, fmt.Errorf("option: %w", err)
		}
	}
	if o.cert == nil {
		return nil, errors.New("cannot sign without a certificate")
	}
	// Extract root namespaces
	if err := addRootNamespaces(o.namespaces, data); err != nil {
		return nil, fmt.Errorf("add root namespaces: %w", err)
	}

	s := &Signature{
		doc:           data,
		opts:          o,
		referenceID:   fmt.Sprintf(referenceIDFormat, o.docID),
		ID:            fmt.Sprintf(signatureRootIDFormat, o.docID),
		DSigNamespace: NamespaceDSig,
	}

	if o.xades != nil {
		s.buildQualifyingProperties()
		// debug
		//ob, _ := xml.Marshal(s.Object)
		//fmt.Printf("s.Object: %s\n", ob)
	}

	s.buildKeyInfo()
	// debug
	//ki, _ := xml.Marshal(s.KeyInfo)
	//fmt.Printf("s.KeyInfo: %s\n", ki)

	if err := s.buildSignedInfo(); err != nil {
		return nil, fmt.Errorf("signed info: %w", err)
	}

	if err := s.buildSignatureValue(); err != nil {
		return nil, fmt.Errorf("signature value: %w", err)
	}

	if o.timestampURL != "" {
		timestamp, timestampErr := buildTimestampValue(s.Value, o.timestampURL)
		if timestampErr != nil {
			return nil, timestampErr
		}
		s.Object.QualifyingProperties.UnsignedProperties = &UnsignedProperties{
			SignatureTimestamp: timestamp,
		}
	}

	return s, nil
}

func addRootNamespaces(ns Namespaces, data []byte) error {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(data); err != nil {
		return fmt.Errorf("reading source data: %w", err)
	}

	for _, a := range d.Root().Attr {
		if a.Space == XMLNS {
			ns[a.Key] = a.Value
		}
	}
	return nil
}

// buildQualifyingProperties is used for the XAdES policy configuration.
func (s *Signature) buildQualifyingProperties() {
	cert := s.opts.cert
	qp := &QualifyingProperties{
		XAdESNamespace: NamespaceXAdES,
		ID:             "", //fmt.Sprintf(sigQualifyingPropertiesIDFormat, s.opts.docID),
		Target:         fmt.Sprintf("#"+signatureRootIDFormat, s.opts.docID),
		SignedProperties: &SignedProperties{
			ID: fmt.Sprintf(sigPropertiesIDFormat, s.opts.docID),
			SignatureProperties: &SignedSignatureProperties{
				SigningTime: s.opts.timeNow().Format(ISO8601),
				SigningCertificate: &SigningCertificate{
					CertDigest: &Digest{
						Method: &AlgorithmMethod{
							Algorithm: AlgEncSHA256,
						},
						Value: cert.Fingerprint(),
					},
					IssuerSerial: &IssuerSerial{
						IssuerName:   cert.Issuer(),
						SerialNumber: cert.SerialNumber(),
					},
				},
				PolicyIdentifier: s.xadesPolicyIdentifier(),
			},
			DataObjectProperties: nil, /* &DataObjectFormat{
				ObjectReference: "#" + s.referenceID,
				Description:     s.opts.xades.Description,
				ObjectIdentifier: &ObjectIdentifier{
					Identifier: &Identifier{
						Qualifier: "OIDAsURN",
						Value:     "urn:oid:1.2.840.10003.5.109.10",
					},
					// Description: "",
				},
				MimeType: "text/xml",
			},*/
		},
	}

	if s.opts.xades.Role != "" {
		qp.SignedProperties.SignatureProperties.SignerRole = &SignerRole{
			ClaimedRoles: &Roles{ClaimedRole: []string{s.opts.xades.Role.String()}},
		}
	}

	s.Object = &Object{
		QualifyingProperties: qp,
	}
}

func (s *Signature) xadesPolicyIdentifier() *PolicyIdentifier {
	policy := s.opts.xades.Policy
	if policy == nil {
		// Return SignaturePolicyImplied when no explicit policy is provided
		return &PolicyIdentifier{
			SigPolicyImplied: &struct{}{},
		}
	}

	return &PolicyIdentifier{
		SigPolicyID: &SigPolicyID{
			Identifier:  policy.URL,
			Description: policy.Description,
		},
		SigPolicyHash: &Digest{
			Method: &AlgorithmMethod{
				Algorithm: policy.Algorithm,
			},
			Value: policy.Hash,
		},
	}
}

func (s *Signature) buildKeyInfo() {
	certificate := s.opts.cert
	info := &KeyInfo{
		ID: fmt.Sprintf(certificateIDFormat, s.opts.docID),
		X509Data: &X509Data{
			X509Certificate: []string{
				certificate.NakedPEM(),
			},
		},
		KeyValue: nil, /*&KeyValue{
			Modulus:  certificate.PrivateKeyInfo().Modulus,
			Exponent: certificate.PrivateKeyInfo().Exponent,
		},*/
	}

	for _, ca := range certificate.CaChain {
		info.X509Data.X509Certificate = append(info.X509Data.X509Certificate, NakedPEM(ca))
	}

	s.KeyInfo = info
}

// buildSignedInfo will add namespaces to the original properties
// as part of canonicalization, so we expect copies here.
func (s *Signature) buildSignedInfo() error {
	si := &SignedInfo{
		CanonicalizationMethod: &AlgorithmMethod{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		},
		SignatureMethod: &AlgorithmMethod{
			Algorithm: s.opts.cert.SignatureAlgorithm(),
		},
		Reference: []*Reference{},
	}

	// Add the document digest
	docDigest, err := digestBytes(s.doc, s.opts.namespaces) // this one is ok
	if err != nil {
		return fmt.Errorf("document digest: %w", err)
	}
	// Use enveloped-signature transform (simpler and may be accepted by KSeF)
	// Remove Type attribute from document reference (compatible with mObywatel format)
	si.Reference = append(si.Reference, &Reference{
		ID:  s.referenceID,
		URI: "",
		Transforms: &Transforms{
			Transform: []*Transform{
				{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
				{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
			},
		},
		DigestMethod: &AlgorithmMethod{
			Algorithm: AlgEncSHA256,
		},
		DigestValue: docDigest,
	})

	// Add the key info
	// ns := s.opts.namespaces.Add(DSig, NamespaceDSig)
	// commented for debug
	/*
		keyInfoDigest, err := digest(s.KeyInfo, s.opts.namespaces)
		if err != nil {
			return fmt.Errorf("key info digest: %w", err)
		}
		si.Reference = append(si.Reference, &Reference{
			URI: "#" + s.KeyInfo.ID,
			DigestMethod: &AlgorithmMethod{
				Algorithm: AlgEncSHA256,
			},
			DigestValue: keyInfoDigest,
		})*/

	// Finally, if present, add the XAdES digests
	if s.opts.xades != nil {
		sp := s.Object.QualifyingProperties.SignedProperties
		// For Exclusive C14N, add both DS and XAdES namespaces to the root of extracted fragment
		// because both are used within SignedProperties subtree but declared in ancestors
		spNamespaces := make(Namespaces)
		spNamespaces = spNamespaces.Add(DSig, NamespaceDSig).Add(XAdES, NamespaceXAdES)

		// DEBUG: Show what we're hashing and save to file
		debugData, _ := xml.Marshal(sp)
		fmt.Printf("\n=== DEBUG: SignedProperties BEFORE canonicalization ===\n%s\n", string(debugData))

		// Save canonicalized version to file for xmlsec comparison
		canonData, canonErr := canonicalize(debugData, spNamespaces)
		if canonErr == nil {
			os.WriteFile("C:\\Users\\mg\\AppData\\Local\\Marcom\\KSeF2-client\\debug_canonicalized_sp.xml", canonData, 0644)
			fmt.Printf("=== Saved canonicalized SignedProperties to debug_canonicalized_sp.xml ===\n")
		}
		// Test: użycie drugiej metody kanonizacji (c14n library - Inclusive C14N)
		// First add namespace declarations manually to the XML string
		xmlWithNS := strings.Replace(string(debugData),
			"<xades:SignedProperties",
			`<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"`,
			1)
		decoder := xml.NewDecoder(strings.NewReader(xmlWithNS))
		canonData2, canonErr2 := c14n.Canonicalize(decoder)
		if canonErr2 == nil {
			os.WriteFile("C:\\Users\\mg\\AppData\\Local\\Marcom\\KSeF2-client\\debug_canonicalized_sp2.xml", canonData2, 0644)
			fmt.Printf("=== Saved c14n library (Inclusive C14N) result to debug_canonicalized_sp2.xml ===\n")
		}

		spDigest, err := digestExclusiveC14N(sp, spNamespaces)
		if err != nil {
			return fmt.Errorf("xades digest: %w", err)
		}
		fmt.Printf("=== SignedProperties digest = %s ===\n", spDigest)
		si.Reference = append(si.Reference, &Reference{
			URI:  "#" + sp.ID,
			Type: "http://uri.etsi.org/01903#SignedProperties",
			Transforms: &Transforms{
				Transform: []*Transform{
					{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
				},
			},
			DigestMethod: &AlgorithmMethod{
				Algorithm: AlgEncSHA256,
			},
			DigestValue: spDigest,
		})
	}

	s.SignedInfo = si
	return nil
}

// newSignatureValue takes a copy of the signedInfo so that we can
// modify the namespaces for canonicalization.
func (s *Signature) buildSignatureValue() error {
	data, err := xml.Marshal(s.SignedInfo)
	if err != nil {
		return err
	}
	ns := s.opts.namespaces.Add(DSig, s.DSigNamespace)
	data, err = canonicalizeExclusiveC14N(data, ns)
	if err != nil {
		return fmt.Errorf("canonicalize SignedInfo: %w", err)
	}

	// DEBUG: Show what we're signing and save to file
	fmt.Printf("\n=== DEBUG: Canonicalized SignedInfo (for signature) ===\n%s\n", string(data))
	os.WriteFile("C:\\Users\\mg\\AppData\\Local\\Marcom\\KSeF2-client\\debug_signedinfo_canonical.xml", data, 0644)

	signatureValue, err := s.opts.cert.Sign(string(data[:]))
	if err != nil {
		return err
	}

	s.Value = &Value{
		ID:    fmt.Sprintf(signatureIDFormat+"-SignatureValue", s.opts.docID),
		Value: signatureValue,
	}
	return nil
}

// UnsignedProperties contains ...
type UnsignedProperties struct {
	SignatureTimestamp *Timestamp `xml:"xades:UnsignedSignatureProperties>xades:SignatureTimestamp"`
}

func currentTime() time.Time {
	return time.Now().UTC()
}
