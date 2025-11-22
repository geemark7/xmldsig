package xmldsig

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	
	"github.com/ucarion/c14n"
)

// digest will create a base64 encoded SHA512 hash of the struct passed as
// parameter (the struct should represent an XML)
func digest(doc interface{}, namespaces Namespaces) (string, error) {
	data, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return digestBytes(data, namespaces)
}

// digestBytes will create a base64 encoded SHA512 hash of the data passed as
// parameter
func digestBytes(data []byte, ns Namespaces) (string, error) {
	out, err := canonicalize(data, ns)
	if err != nil {
		return "", err
	}
	
	sum := sha256.Sum256(out)
	//sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// digestExclusiveC14N uses the c14n library for proper Exclusive C14N canonicalization
func digestExclusiveC14N(doc interface{}, ns Namespaces) (string, error) {
	data, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}
	
	// Add namespace declarations to root element manually
	xmlStr := string(data)
	for prefix, uri := range ns {
		nsDecl := fmt.Sprintf(` xmlns:%s="%s"`, prefix, uri)
		xmlStr = strings.Replace(xmlStr, ">", nsDecl+">", 1)
	}
	
	// Use c14n library for proper Exclusive C14N
	decoder := xml.NewDecoder(strings.NewReader(xmlStr))
	canonicalized, err := c14n.Canonicalize(decoder)
	if err != nil {
		return "", err
	}
	
	sum := sha256.Sum256(canonicalized)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

