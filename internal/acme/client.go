package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// CertResult represents the result of a certificate issuance.
type CertResult struct {
	Domain     string
	CertPath   string
	KeyPath    string
	CertPEM    string
	KeyPEM     string
	IssueDate  time.Time
	ExpiryDate time.Time
}

// User implements the acme.User interface for lego.
type User struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// Client wraps the lego ACME client.
type Client struct {
	certDir    string
	staging    bool
	httpPort   string
	webrootDir string
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// WithCertDir sets the certificate storage directory.
func WithCertDir(dir string) ClientOption {
	return func(c *Client) { c.certDir = dir }
}

// WithStaging enables the Let's Encrypt staging environment.
func WithStaging(staging bool) ClientOption {
	return func(c *Client) { c.staging = staging }
}

// WithHTTPPort sets the port for HTTP-01 challenge (default: ":80").
func WithHTTPPort(port string) ClientOption {
	return func(c *Client) { c.httpPort = port }
}

// WithWebrootDir sets the webroot directory for webroot challenge mode.
func WithWebrootDir(dir string) ClientOption {
	return func(c *Client) { c.webrootDir = dir }
}

// NewClient creates a new ACME client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		certDir:  "/etc/miaomiaowu/certs",
		staging:  false,
		httpPort: ":80",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ObtainCertificate requests a new certificate for the given domain.
func (c *Client) ObtainCertificate(ctx context.Context, email, domain string, useWebroot bool) (*CertResult, error) {
	if email == "" {
		return nil, errors.New("email is required")
	}
	if domain == "" {
		return nil, errors.New("domain is required")
	}

	// Generate a new private key for the user
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	user := &User{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(user)
	if c.staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}
	config.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create lego client: %w", err)
	}

	// Set up HTTP-01 challenge provider
	if useWebroot && c.webrootDir != "" {
		// Webroot mode: write challenge files to the specified directory
		provider, err := NewWebrootProvider(c.webrootDir)
		if err != nil {
			return nil, fmt.Errorf("create webroot provider: %w", err)
		}
		if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
			return nil, fmt.Errorf("set webroot provider: %w", err)
		}
	} else {
		// Standalone mode: lego starts its own HTTP server
		provider := http01.NewProviderServer("", c.httpPort)
		if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
			return nil, fmt.Errorf("set http01 provider: %w", err)
		}
	}

	// Register the user
	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, fmt.Errorf("register with ACME: %w", err)
	}
	user.Registration = reg

	// Request the certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}

	// Parse the certificate to get expiry date
	expiryDate, issueDate, err := parseCertificateDates(certificates.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// Save the certificate to disk
	certPath, keyPath, err := c.saveCertificate(domain, certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("save certificate: %w", err)
	}

	return &CertResult{
		Domain:     domain,
		CertPath:   certPath,
		KeyPath:    keyPath,
		CertPEM:    string(certificates.Certificate),
		KeyPEM:     string(certificates.PrivateKey),
		IssueDate:  issueDate,
		ExpiryDate: expiryDate,
	}, nil
}

func (c *Client) saveCertificate(domain string, certPEM, keyPEM []byte) (string, string, error) {
	// Ensure directory exists
	domainDir := filepath.Join(c.certDir, domain)
	if err := os.MkdirAll(domainDir, 0700); err != nil {
		return "", "", fmt.Errorf("create cert directory: %w", err)
	}

	certPath := filepath.Join(domainDir, "fullchain.pem")
	keyPath := filepath.Join(domainDir, "privkey.pem")

	// Write certificate
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return "", "", fmt.Errorf("write certificate: %w", err)
	}

	// Write private key with restrictive permissions
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write private key: %w", err)
	}

	return certPath, keyPath, nil
}

func parseCertificateDates(certPEM []byte) (expiryDate, issueDate time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, time.Time{}, errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}

	return cert.NotAfter, cert.NotBefore, nil
}

// GetCertDir returns the certificate storage directory.
func (c *Client) GetCertDir() string {
	return c.certDir
}
