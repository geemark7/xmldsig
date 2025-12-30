# XML-DSig (polska wersja README)

Opis
-
Biblioteka do generowania podpisów XML zgodnych z XML-DSig, z elementami XAdES oraz opcjonalnym znacznikiem czasu (TSA). Umożliwia tworzenie podpisów typu enveloped dla dokumentów XML i zawiera pomocnicze funkcje do ładowania certyfikatów PKCS#12 oraz przygotowania konfiguracji TLS. 

Ta biblioteka jest forkiem projektu [invopop/xmldsig](https://github.com/invopop/xmldsig) i została dostosowana do współpracy z polskim systemem faktur elektronicznych KSeF.

Obsługiwane algorytmy i cechy
-
- klucze RSA i ECDSA dla podpisów.
- Wykorzystanie Exclusive Canonicalization (Exclusive C14N) przy pomocy `github.com/ucarion/c14n` dla `SignedInfo` i `SignedProperties`.
- Generowanie XAdES `QualifyingProperties` (m.in. `SigningTime`, `SigningCertificate`, opcjonalny `SignerRole`).
- Opcjonalne dodanie znacznika czasu (TSA) przez `WithTimestamp`.
- Ładowanie certyfikatów z plików PKCS#12 (`.p12`, `.pfx`) przez `LoadCertificate`.
- Pomocnicze metody certyfikatu: `Fingerprint()`, `NakedPEM()`, `PEM()`, `PrivateKey()`, `TLSAuthConfig()`.

Instalacja
-
Użyj standardowego polecenia Go:

```bash
go get github.com/geemark7/xmldsig
```

Szybkie użycie
-
1) Załaduj certyfikat PKCS#12 i podpisz dane:

```go
cert, err := xmldsig.LoadCertificate("./cert.p12", "haslo")
if err != nil {
    // obsłuż błąd
}
sig, err := xmldsig.Sign(data,
    xmldsig.WithCertificate(cert),
    xmldsig.WithXAdES(&xmldsig.XAdESConfig{Role: xmldsig.XAdESSignerRole("signer")}),
    xmldsig.WithTimestamp(xmldsig.TimestampFreeTSA),
)
if err != nil {
    // obsłuż błąd
}
// Dołącz `sig` do głównej struktury XML (pole np. `xml:"ds:Signature,omitempty"`) i wyemituj dokument
```

3) Przykład pochodzący z klienta KSeF.

```go

// struktura dokumentu xml wymagającego podpisu
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

// signXMLWithXAdESFromP12 tworzy podpis XAdES z pliku PKCS#12
func signXMLWithXAdESFromP12(authRequest *AuthTokenRequest, p12Path, pin string) ([]byte, error) {
	// Wczytaj certyfikat z pliku PKCS#12
	cert, err := xmldsig.LoadCertificate(p12Path, pin)
	if err != nil {
		return nil, fmt.Errorf("loading certificate from P12: %w", err)
	}

	// Konfiguracja XAdES
	xades := &xmldsig.XAdESConfig{
		Role:        xmldsig.XAdESSignerRole(""),
		Description: "",
	}

	// Marshal dokumentu do XML
	xmlBytes, err := xml.Marshal(authRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal xml: %w", err)
	}

	// Utwórz podpis XAdES
	signature, err := xmldsig.Sign(xmlBytes,
		xmldsig.WithCertificate(cert),
		xmldsig.WithXAdES(xades),
	)
	if err != nil {
		return nil, fmt.Errorf("create XAdES signature: %w", err)
	}

	// Dodaj podpis do dokumentu
	authRequest.Signature = signature
	out, err := xml.Marshal(authRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal signed xml: %w", err)
	}

	return out, nil
}
```

Opcje podpisywania
-
W kodzie biblioteki funkcja `Sign` przyjmuje opcje:
- `WithCertificate(cert *Certificate)` — wymagane do podpisania.
- `WithXAdES(config *XAdESConfig)` — tworzy `QualifyingProperties` (XAdES).
- `WithTimestamp(url string)` — dodaje podpisane dane czasowe z usługi TSA (Time Stamping Authority).
- `WithNamespace(name, url string)` — pozwala dołączyć dodatkowe przestrzenie nazw używane przy kanonikalizacji.
- `WithDocID(id string)` — nadpisuje wewnętrzne ID dokumentu.
- `WithCurrentTime(fn func() time.Time)` — umożliwia testowe ustawienie czasu podpisu.

Certyfikaty
-
- Biblioteka oczekuje certyfikatów w formacie PKCS#12 (plik `.p12`/`.pfx`).
- Jeśli masz certyfikat w formacie PEM/X.509, konwertuj go przy pomocy OpenSSL. Przykładowe polecenia opisano w oryginalnym README.
- Kolejność certyfikatów w PKCS#12 ma znaczenie — certyfikat główny powinien być pierwszy.

Uwagi techniczne
-
- Kanonikalizacja: biblioteka stosuje własne funkcje porządkowania atrybutów i usuwania duplikatów przestrzeni nazw oraz używa `github.com/ucarion/c14n` dla Exclusive C14N tam, gdzie jest to wymagane.
- Podpisy ECDSA są generowane w formacie R||S zgodnym z XML-DSig (nie w ASN.1 DER).
- Domyślne algorytmy: SHA-256 dla digestów i podpisów.
- Dla kompatybilności z konkretnymi systemami sprawdź transformy i identyfikatory referencji w implementacji (patrz `signature.go`).

Licencja
-
Projekt jest udostępniony na licencji Apache 2.0.

---
Plik `README_PL.md` jest wersją roboczą po polsku. Gdy potwierdzisz treść, przygotuję tłumaczenie aktualizujące `README.md` (wersja angielska).