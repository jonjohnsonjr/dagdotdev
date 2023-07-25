package apk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func renderCert(w io.Writer, b []byte, u url.URL) error {
	qs := u.Query()
	qs.Set("render", "x509")
	u.RawQuery = qs.Encode()

	fmt.Fprintf(w, `<div><a href="%s">`, u.String())

	for _, line := range bytes.Split(b, []byte("\n")) {
		if _, err := w.Write(line); err != nil {
			return err
		}
		fmt.Fprintf(w, "<br>\n")
	}
	fmt.Fprintf(w, "</a>\n</div>")

	return nil
}

// TODO: render links!
// TODO: Don't use x509.ParseCertificate
func renderDer(w io.Writer, b []byte) error {
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "<pre>")
	fmt.Fprintf(w, "Certificate:\n")
	fmt.Fprintf(w, "    Data:\n")
	fmt.Fprintf(w, "        Version: %d (0x%x)\n", cert.Version, cert.Version-1)

	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		fmt.Fprintf(w, "        Serial Number:\n")
		fmt.Fprintf(w, "            ")
		printHex(w, cert.SerialNumber.Bytes())
		fmt.Fprintf(w, "\n")
	} else {
		fmt.Fprintf(w, "        Serial Number: %d (%#x)\n", cert.SerialNumber, cert.SerialNumber)
	}

	fmt.Fprintf(w, "        Signature Algorithm: %s\n", alg(cert.SignatureAlgorithm.String()))
	fmt.Fprintf(w, "        Issuer: %s\n", pkixname(cert.Issuer))
	fmt.Fprintf(w, "        Validity\n")
	fmt.Fprintf(w, "            Not Before: %s\n", cert.NotBefore.Format("Jan _2 15:04:05 2006 GMT"))
	fmt.Fprintf(w, "            Not After : %s\n", cert.NotAfter.Format("Jan _2 15:04:05 2006 GMT"))
	fmt.Fprintf(w, "        Subject: %s\n", pkixname(cert.Subject))
	fmt.Fprintf(w, "        Subject Public Key Info:\n")
	fmt.Fprintf(w, "            Public Key Algorithm: %s\n", alg(cert.PublicKeyAlgorithm.String()))

	pub := cert.PublicKey
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		bits := p.Params().BitSize
		name := p.Params().Name

		fmt.Fprintf(w, "                Public-Key: (%d bit)\n", bits)
		fmt.Fprintf(w, "                pub:")
		bs := []byte{0x04} // uncompressed public keys start with 04?
		bs = append(bs, p.X.Bytes()...)
		bs = append(bs, p.Y.Bytes()...)
		for i, b := range bs {
			if i%15 == 0 {
				fmt.Fprintf(w, "\n                    ")
			}
			fmt.Fprintf(w, "%02x", b)
			if i < len(bs)-1 {
				fmt.Fprintf(w, ":")
			} else {
				fmt.Fprintf(w, "\n")
			}
		}
		if name == "P-256" {
			fmt.Fprintf(w, "                ASN1 OID: prime256v1\n")
		}
		fmt.Fprintf(w, "                NIST CURVE: %s\n", name)

	case *rsa.PublicKey:
		bits := p.N.BitLen()

		fmt.Fprintf(w, "                Public-Key: (%d bit)\n", bits)
		fmt.Fprintf(w, "                Modulus:")
		bs := []byte{0x00} // uncompressed public keys start with 04?
		bs = append(bs, p.N.Bytes()...)
		for i, b := range bs {
			if i%15 == 0 {
				fmt.Fprintf(w, "\n                    ")
			}
			fmt.Fprintf(w, "%02x", b)
			if i < len(bs)-1 {
				fmt.Fprintf(w, ":")
			} else {
				fmt.Fprintf(w, "\n")
			}
		}
		fmt.Fprintf(w, "                Exponent: %d (%#x)\n", p.E, p.E)

	default:
		return fmt.Errorf("TODO: renderx509 with %T", pub)
	}

	fmt.Fprintf(w, "        X509v3 extensions:\n")
	for _, ext := range cert.Extensions {
		fmt.Fprintf(w, "            %s: ", oidKey(ext.Id))
		if ext.Critical {
			fmt.Fprintf(w, "critical")
		}
		fmt.Fprintf(w, "\n")
		h := find(ext.Id)
		if h != nil && h.format != nil {
			for _, line := range strings.Split(h.format(cert, ext.Value), "\n") {
				fmt.Fprintf(w, "                %s\n", line)
			}
		} else {
			fmt.Fprintf(w, "                %v\n", asn1debug(cert, ext.Value))
		}
	}

	fmt.Fprintf(w, "    Signature Algorithm: %s\n", alg(cert.SignatureAlgorithm.String()))
	fmt.Fprintf(w, "    Signature Value:")
	for i, b := range cert.Signature {
		if i%18 == 0 {
			fmt.Fprintf(w, "\n        ")
		}
		fmt.Fprintf(w, "%02x", b)
		if i < len(cert.Signature)-1 {
			fmt.Fprintf(w, ":")
		} else {
			fmt.Fprintf(w, "\n")
		}

	}
	fmt.Fprintf(w, "</pre>")
	return nil
}

func renderx509(w io.Writer, b []byte) error {
	block, rest := pem.Decode(b)
	for {
		if block == nil {
			return fmt.Errorf("pem.Decode: %v, %d", block, len(rest))
		}
		if err := renderDer(w, block.Bytes); err != nil {
			return err
		}
		if len(rest) == 0 {
			break
		}
		block, rest = pem.Decode(rest)
	}
	return nil
}

func printHex(w io.Writer, bs []byte) {
	for i, b := range bs {
		fmt.Fprintf(w, "%02x", b)
		if i < len(bs)-1 {
			fmt.Fprintf(w, ":")
		}
	}
}

func printHEX(w io.Writer, bs []byte) {
	for i, b := range bs {
		fmt.Fprintf(w, "%02X", b)
		if i < len(bs)-1 {
			fmt.Fprintf(w, ":")
		}
	}
}

type oidHelper struct {
	Id     asn1.ObjectIdentifier
	Name   string
	format func(*x509.Certificate, []byte) string
}

func (lhs *oidHelper) Equals(rhs asn1.ObjectIdentifier) bool {
	if len(lhs.Id) != len(rhs) {
		return false
	}
	for i, l := range lhs.Id {
		if l != rhs[i] {
			return false
		}
	}
	return true
}

func find(id asn1.ObjectIdentifier) *oidHelper {
	for _, h := range helpers {
		if h.Equals(id) {
			return &h
		}
	}
	return nil
}

func oidKey(id asn1.ObjectIdentifier) string {
	h := find(id)
	if h == nil {
		return id.String()
	}

	return h.Name
}

var helpers = []oidHelper{
	{[]int{2, 5, 29, 15}, "X509v3 Key Usage", keyUsage},
	{[]int{2, 5, 29, 37}, "X509v3 Extended Key Usage", extKeyUsage},
	{[]int{2, 5, 29, 14}, "X509v3 Subject Key Identifier", octet},
	{[]int{2, 5, 29, 35}, "X509v3 Authority Key Identifier", sequence},
	{[]int{2, 5, 29, 17}, "X509v3 Subject Alternative Name", printSan},
	{[]int{2, 5, 29, 19}, "X509v3 Basic Constraints", constraints},
	{[]int{1, 3, 6, 1, 4, 1, 57264, 1, 1}, "Fulcio Issuer", nil},
	{[]int{1, 3, 6, 1, 4, 1, 57264, 1, 2}, "GitHub Workflow Trigger", nil},
	{[]int{1, 3, 6, 1, 4, 1, 57264, 1, 3}, "GitHub Workflow SHA", nil},
	{[]int{1, 3, 6, 1, 4, 1, 57264, 1, 4}, "GitHub Workflow Name", nil},
	{[]int{1, 3, 6, 1, 4, 1, 57264, 1, 5}, "GitHub Workflow Repository", nil},
	{[]int{1, 3, 6, 1, 4, 1, 57264, 1, 6}, "GitHub Workflow Ref", nil},
	{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, "CT Precertificate SCTs", printSCTs},
}

func constraints(cert *x509.Certificate, b []byte) string {
	w := &strings.Builder{}
	if cert.IsCA {
		w.WriteString("CA:TRUE")
	} else {
		w.WriteString("CA:FALSE")
	}

	if cert.MaxPathLenZero {
		w.WriteString(", pathlen:0")
	} else if cert.MaxPathLen > 0 {
		fmt.Fprintf(w, ", pathlen:%d", cert.MaxPathLen)
	}
	return w.String()
}

func alg(in string) string {
	switch in {
	case "ECDSA":
		return "id-ecPublicKey"
	case "ECDSA-SHA256":
		return "ecdsa-with-SHA256"
	case "ECDSAWithP256AndSHA256":
		return "ecdsa-with-SHA256"
	case "ECDSA-SHA384":
		return "ecdsa-with-SHA384"
	case "SHA256-RSA":
		return "sha256WithRSAEncryption"
	case "RSA":
		return "rsaEncryption"
	}
	return in
}

// Subject: CN=sample-network.io,O=Notary,L=Seattle,ST=WA,C=US
// Subject: C = US, ST = WA, L = Seattle, O = Notary, CN = sample-network.io
func pkixname(name pkix.Name) string {
	s := name.String()
	chunks := strings.Split(s, ",")
	reverse(chunks)
	for i, chunk := range chunks {
		chunks[i] = strings.Join(strings.Split(chunk, "="), " = ")
	}
	return strings.Join(chunks, ", ")
}

func reverse(in []string) {
	for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
		in[i], in[j] = in[j], in[i]
	}
}

var keyUsages = []struct {
	KeyUsage x509.KeyUsage
	Name     string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

func keyUsage(cert *x509.Certificate, b []byte) string {
	kus := []string{}
	for _, ku := range keyUsages {
		if ku.KeyUsage&cert.KeyUsage != 0 {
			kus = append(kus, ku.Name)
		}
	}
	if len(kus) > 0 {
		return strings.Join(kus, ", ")
	}
	return "None"
}

var extKeyUsages = []struct {
	KeyUsage x509.ExtKeyUsage
	Name     string
}{
	{x509.ExtKeyUsageAny, "Any Usage"},
	{x509.ExtKeyUsageServerAuth, "TLS Web Server Authentication"},
	{x509.ExtKeyUsageClientAuth, "TLS Web Client Authentication"},
	{x509.ExtKeyUsageCodeSigning, "Code Signing"},
	{x509.ExtKeyUsageEmailProtection, "Email Protection"},
	{x509.ExtKeyUsageIPSECEndSystem, "IPSEC End System"},
	{x509.ExtKeyUsageIPSECTunnel, "IPSEC Tunnel"},
	{x509.ExtKeyUsageIPSECUser, "UPSEC User"},
	{x509.ExtKeyUsageTimeStamping, "Time Stamping"},
	{x509.ExtKeyUsageOCSPSigning, "OCSP Signing"},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "Microsoft Server Gated Crypto"},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, "Netscape Server Gated Crypto"},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "Microsoft Commercial Code Signing"},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "Microsoft Kernel Code Signing"},
}

func extKeyUsage(cert *x509.Certificate, b []byte) string {
	kus := []string{}
	for _, eku := range cert.ExtKeyUsage {
		for _, ku := range extKeyUsages {
			if ku.KeyUsage == eku {
				kus = append(kus, ku.Name)
				break
			}
		}
	}
	if len(kus) > 0 {
		return strings.Join(kus, ", ")
	}
	return "None"
}

func octet(cert *x509.Certificate, b []byte) string {
	cb := cryptobyte.String(b)
	var out []byte
	if !cb.ReadASN1Bytes(&out, casn1.OCTET_STRING) {
		return "oops"
	}
	return HEXIFY(cert, out)
}

func sequence(cert *x509.Certificate, b []byte) string {
	cb := cryptobyte.String(b)
	var out []byte
	if !cb.ReadASN1Bytes(&out, casn1.SEQUENCE) {
		return "oops"
	}
	if len(out) > 2 {
		newlen := out[1]
		if int(newlen) <= len(out)-2 {
			return HEXIFY(cert, out[2:2+newlen])
		}
	}
	return HEXIFY(cert, out)
}

func hexify(cert *x509.Certificate, b []byte) string {
	w := &strings.Builder{}
	printHex(w, b)
	return w.String()
}

func HEXIFY(cert *x509.Certificate, b []byte) string {
	w := &strings.Builder{}
	printHEX(w, b)
	return w.String()
}

func printSan(cert *x509.Certificate, b []byte) string {
	names := [][]string{{}, {}, {}, {}}
	for _, dns := range cert.DNSNames {
		names[0] = append(names[0], "dns:"+dns)
	}
	for _, email := range cert.EmailAddresses {
		names[1] = append(names[1], "email:"+email)
	}
	for _, ip := range cert.IPAddresses {
		names[2] = append(names[2], "ip:"+ip.String())
	}
	for _, uri := range cert.URIs {
		names[3] = append(names[3], "uri:"+uri.String())
	}
	outs := []string{}
	for _, name := range names {
		if len(name) != 0 {
			outs = append(outs, strings.Join(name, ", "))
		}
	}

	return strings.Join(outs, "\n")
}

func printSCTs(cert *x509.Certificate, b []byte) string {
	cb := cryptobyte.String(b)
	var out []byte
	if !cb.ReadASN1Bytes(&out, casn1.OCTET_STRING) {
		return "oops"
	}

	ss, err := parseScts(out)
	if err != nil {
		return err.Error()
	}

	w := &strings.Builder{}
	for _, s := range ss {
		w.WriteString(s.String())
	}
	return w.String()
}

func parseScts(b []byte) ([]*sct, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("len only %d", len(b))
	}

	hdr := b[:2]
	if hdr[0] != 0 {
		return nil, fmt.Errorf("hdr[0] = %d", hdr[0])
	}

	l := int(hdr[1])
	if l != len(b)-2 {
		return nil, fmt.Errorf("l = %d", l)
	}

	scts := []*sct{}
	c := b[2:]
	for {
		if len(c) < 2 {
			return nil, fmt.Errorf("len only %d", len(c))
		}
		hdr := c[:2]
		if hdr[0] != 0 {
			return nil, fmt.Errorf("hdr[0] = %d", hdr[0])
		}

		l := int(hdr[1])

		rest := c[2:]

		if l < len(rest) {
			return nil, fmt.Errorf("l (%d) < len(rest) (%d)", l, len(rest))
		}
		s, err := parseSct(rest[:l])
		if err != nil {
			return nil, err
		}
		scts = append(scts, s)

		if l == len(rest) {
			break
		}
		c = rest
	}

	return scts, nil
}

func parseSct(b []byte) (*sct, error) {
	if len(b) < 41 {
		return nil, fmt.Errorf("len(b) only %d", len(b))
	}

	s := sct{}

	s.Version = int(b[0])
	s.LogID = b[1:33]

	rest := b[33:]
	if len(rest) < 2 {
		return nil, fmt.Errorf("len(rest) only %d", len(rest))
	}
	ts := binary.BigEndian.Uint64(rest[:8])
	s.Timestamp = time.UnixMilli(int64(ts))
	rest = rest[8:]

	// Extensions
	hdr := rest[:2]
	if hdr[0] != 0 {
		return nil, fmt.Errorf("hdr[0] = %d", hdr[0])
	}
	l := int(hdr[1])
	if l != 0 {
		return nil, fmt.Errorf("TODO: handle SCT extensions, l = %d", l)
	}

	rest = rest[2:]
	if len(rest) < 2 {
		return nil, fmt.Errorf("len(rest) only %d", len(rest))
	}
	s.SigHashAlg = tls.SignatureScheme(binary.BigEndian.Uint16(rest[:2]))

	if len(rest) < 2 {
		return nil, fmt.Errorf("len(rest) only %d", len(rest))
	}
	rest = rest[2:]

	// Signature
	hdr = rest[:2]
	if hdr[0] != 0 {
		return nil, fmt.Errorf("hdr[0] = %d", hdr[0])
	}
	l = int(hdr[1])
	if l != len(rest)-2 {
		return nil, fmt.Errorf("len(rest) = %d, l = %d", len(rest), l)
	}
	s.Sig = rest[2:]

	return &s, nil
}

type sct struct {
	Version    int
	LogID      []byte
	Timestamp  time.Time
	Extensions [][]byte
	SigHashAlg tls.SignatureScheme
	Sig        []byte
}

func (s *sct) String() string {
	w := &strings.Builder{}
	fmt.Fprintf(w, "Signed Certificate Timestamp:\n")
	fmt.Fprintf(w, "    Version   : v%d (0x%x)\n", s.Version+1, s.Version)
	fmt.Fprintf(w, "    Log ID    : ")
	for i, b := range s.LogID {
		if i != 0 && i%16 == 0 {
			fmt.Fprintf(w, "\n                ")
		}
		fmt.Fprintf(w, "%02X", b)
		if i < len(s.LogID)-1 {
			fmt.Fprintf(w, ":")
		} else {
			fmt.Fprintf(w, "\n")
		}
	}
	fmt.Fprintf(w, "    Timestamp : %s\n", s.Timestamp.UTC().Format("Jan _2 15:04:05.999 2006 GMT"))
	if len(s.Extensions) == 0 {
		fmt.Fprintf(w, "    Extensions: none\n")
	} else {
		fmt.Fprintf(w, "    Extensions: TODO render %d extensions\n", len(s.Extensions))
	}
	fmt.Fprintf(w, "    Signature : %s", alg(s.SigHashAlg.String()))
	for i, b := range s.Sig {
		if i%16 == 0 {
			fmt.Fprintf(w, "\n                ")
		}
		fmt.Fprintf(w, "%02X", b)
		if i < len(s.Sig)-1 {
			fmt.Fprintf(w, ":")
		}
	}
	return w.String()
}

func asn1debug(cert *x509.Certificate, b []byte) string {
	var (
		outTag casn1.Tag
		out    cryptobyte.String
	)
	cb := cryptobyte.String(b)

	if cb.ReadAnyASN1(&out, &outTag) {
		// TODO: What?
	} else {
		return string(b)
	}

	return hexify(cert, b)
}
