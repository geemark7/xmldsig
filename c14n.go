package xmldsig

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"

	"github.com/beevik/etree"
	"github.com/ucarion/c14n"
)

// canonicalize will take the data and attempt to combine the namespaces provided.
// It doesn't do much more than that, as the golang xml lib already does most of the
// work of creating standard XML.
func canonicalize(data []byte, ns Namespaces) ([]byte, error) {
	d := etree.NewDocument()
	d.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}
	d.Indent(etree.NoIndent)
	if err := d.ReadFromBytes(data); err != nil {
		return nil, err
	}

	r := d.Root()

	// Add any missing namespaces
	for _, v := range ns.defs() {
		match := false
		for _, a := range r.Attr {
			if a.Space == v.Space && a.Key == v.Key {
				match = true
			}
		}
		if !match {
			r.Attr = append(r.Attr, v)
		}
	}
	sort.Sort(byCanonicalAttr(r.Attr))

	// Remove duplicate namespace declarations from child elements
	// that are already declared in root
	removeDuplicateNamespaces(r, ns)

	return d.WriteToBytes()
}

// removeDuplicateNamespaces recursively removes namespace declarations from child elements
// that are already declared in the root element
func removeDuplicateNamespaces(elem *etree.Element, rootNS Namespaces) {
	// Check all child elements
	for _, child := range elem.ChildElements() {
		// Remove namespace attributes that are already in root
		newAttrs := []etree.Attr{}
		for _, attr := range child.Attr {
			// Check if this is a namespace declaration
			if attr.Space == XMLNS {
				// Check if it's already in root namespaces
				if rootValue, exists := rootNS[attr.Key]; exists && rootValue == attr.Value {
					// Skip this attribute - it's duplicate
					continue
				}
			}
			newAttrs = append(newAttrs, attr)
		}
		child.Attr = newAttrs

		// Recursively process this child's children
		removeDuplicateNamespaces(child, rootNS)
	}
}

type byCanonicalAttr []etree.Attr

func (a byCanonicalAttr) Len() int {
	return len(a)
}

func (a byCanonicalAttr) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a byCanonicalAttr) Less(i, j int) bool {
	// Canonical XML ordering (C14N and Exclusive C14N):
	// 1. Namespace declarations come FIRST (sorted by prefix name, not URI)
	// 2. Regular attributes come AFTER (sorted by namespace URI, then by local name)

	// Check if these are namespace declarations
	iIsNS := a[i].Space == XMLNS
	jIsNS := a[j].Space == XMLNS

	// If both are namespace declarations, sort by prefix (Key)
	if iIsNS && jIsNS {
		// Default namespace (xmlns="...") has empty Key and comes first
		if a[i].Key == "" {
			return true
		}
		if a[j].Key == "" {
			return false
		}
		// Otherwise sort by prefix name lexicographically
		return strings.Compare(a[i].Key, a[j].Key) < 0
	}

	// Namespace declarations come before regular attributes
	if iIsNS && !jIsNS {
		return true
	}
	if !iIsNS && jIsNS {
		return false
	}

	// Both are regular attributes - sort by namespace URI, then by local name
	// Resolve namespace URI from Space (which is the prefix)
	is := a[i].Space
	js := a[j].Space

	// Find the actual namespace URI for each prefix
	for _, v := range a {
		if v.Space == XMLNS {
			if v.Key == a[i].Space {
				is = v.Value
			}
			if v.Key == a[j].Space {
				js = v.Value
			}
		}
	}

	// Compare by namespace URI first
	sp := strings.Compare(is, js)
	if sp == 0 {
		// Same namespace - compare by local name
		return strings.Compare(a[i].Key, a[j].Key) < 0
	}
	return sp < 0
}

// canonicalizeExclusiveC14N performs Exclusive Canonical XML (C14N) using the c14n library.
// This is the proper implementation for XML-DSig that follows the Exclusive C14N specification
// where namespaces are added only to elements that use them, not to the root element.
func canonicalizeExclusiveC14N(data []byte, ns Namespaces) ([]byte, error) {
	// Parse the XML to check if namespaces are already declared
	xmlStr := string(data)

	// Add missing namespace declarations to the root element
	// Only add if not already present in the XML string
	for prefix, uri := range ns {
		nsDecl := fmt.Sprintf(`xmlns:%s="%s"`, prefix, uri)
		if !strings.Contains(xmlStr, nsDecl) {
			// Add namespace declaration before the first >
			nsAttr := fmt.Sprintf(` xmlns:%s="%s"`, prefix, uri)
			xmlStr = strings.Replace(xmlStr, ">", nsAttr+">", 1)
		}
	}

	// Use the c14n library for proper Exclusive C14N
	decoder := xml.NewDecoder(strings.NewReader(xmlStr))
	canonData, err := c14n.Canonicalize(decoder)
	if err != nil {
		return nil, fmt.Errorf("c14n canonicalize: %w", err)
	}

	return canonData, nil
}
