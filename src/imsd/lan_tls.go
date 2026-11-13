package main

// SIP over TLS for the phones: the server certificate. The router has no name
// a public CA would sign, so the daemon makes a self-signed certificate for
// its LAN address and keeps it in /etc/mudi-volte. Linphone cannot pin a
// certificate from its configuration (liblinphone reads only a CA file path,
// root_ca, and a subject regexp), so phone setup by QR code turns the server
// certificate check off: TLS then keeps the SIP messages and the SRTP keys in
// them from anyone listening on the Wi-Fi, but does not prove to the phone
// that it talks to this router.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	tlsCertLifetime = 10 * 365 * 24 * time.Hour
	// tlsCertRenewBefore: a certificate this close to its end is made anew.
	tlsCertRenewBefore = 30 * 24 * time.Hour
)

// serverCertificate returns the certificate for ip from certFile and keyFile.
// A missing or unreadable pair, one for another address or one near its end
// is replaced by a new self-signed one. made reports a new certificate.
func serverCertificate(certFile, keyFile string, ip net.IP, now time.Time) (cert tls.Certificate, made bool, err error) {
	if c, err := loadCertificate(certFile, keyFile); err == nil {
		if leaf := c.Leaf; leaf != nil && certCovers(leaf, ip) && now.Add(tlsCertRenewBefore).Before(leaf.NotAfter) {
			return c, false, nil
		}
	}
	certPEM, keyPEM, err := selfSignedCertificate(ip, now)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writePEMFile(keyFile, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writePEMFile(certFile, certPEM, 0o644); err != nil {
		return tls.Certificate{}, false, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	return c, true, nil
}

func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return tls.Certificate{}, err
		}
	}
	return c, nil
}

func certCovers(leaf *x509.Certificate, ip net.IP) bool {
	for _, a := range leaf.IPAddresses {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

// selfSignedCertificate makes an ECDSA P-256 certificate for ip, valid from an
// hour before now (the router's clock may still be catching up) for ten years.
func selfSignedCertificate(ip net.IP, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ip.String(), Organization: []string{"mudi-volte"}},
		IPAddresses:           []net.IP{ip},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(tlsCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// certFingerprint is the SHA-256 of the certificate, as phones and openssl show it.
func certFingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// tlsServerConfig: TLS 1.2 and up with Go's default suites; Linphone (mbedTLS)
// speaks both 1.2 and 1.3.
func tlsServerConfig(c tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
}

// writePEMFile writes the file with mode perm through a temporary one in the
// same directory and a rename (the directory is made when missing).
func writePEMFile(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
