package certlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	cr "github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"
)

// Config holds the configuration for the certificate library.
type Config struct {
	Domain               string
	ClientID             string
	ResponseType         string
	Scope                string
	GenerateChallengeURI string
	SubmitChallengeURI   string
	GrantType            string
	PrivateKeyPEMType    string
	CertificatePEMType   string
	Logger               zerolog.Logger
	HTTPClient           *http.Client
}

// NewDefaultConfig creates a default configuration.
func NewDefaultConfig() *Config {
	return &Config{
		Domain:               "http://127.0.0.1:10000",
		ClientID:             "step-ca",
		ResponseType:         "code",
		Scope:                "openid email",
		GenerateChallengeURI: "/auth/web3/generate_challenge",
		SubmitChallengeURI:   "/auth/web3/submit_challenge",
		GrantType:            "authorization_code",
		PrivateKeyPEMType:    "EC PRIVATE KEY",
		CertificatePEMType:   "CERTIFICATE",
		Logger:               zerolog.New(os.Stdout).With().Timestamp().Logger(),
		HTTPClient:           http.DefaultClient,
	}
}

// CertLib provides methods for requesting certificates.
type CertLib struct {
	Config *Config
}

// NewCertLib creates a new CertLib instance with the given configuration.
func NewCertLib(config *Config) *CertLib {
	return &CertLib{Config: config}
}

type ChallengeResponse struct {
	State     string `json:"state"`
	Challenge string `json:"challenge"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

// RequestCertificates requests a certificate from step-ca using the provided parameters.
// It performs the following steps:
// 1. Retrieves an OAuth token by signing a challenge with the provided Ethereum private key.
// 2. Uses the token to create and sign a certificate request with step-ca.
// 3. Returns the signed certificate and private key in PEM format.
//
// Parameters:
// - ethAddress: The Ethereum address used to sign the challenge.
// - privateKey: The private key corresponding to the Ethereum address.
// - clientSecret: The client secret for OAuth authentication.
// - oauthURL: The URL of the OAuth server to generate and submit the challenge.
// - stepCAUrl: The URL of the step-ca server to sign the certificate.
// - fingerprint: The SHA256 fingerprint of the step-ca root certificate.
// - connectionAddr: The connection address to be included in the certificate's Common Name.
//
// Returns:
// - A string containing the signed certificate in PEM format.
// - A string containing the private key in PEM format.
// - An error if any step in the process fails.
func (c *CertLib) RequestCertificates(
	ethAddress *common.Address,
	privateKey *ecdsa.PrivateKey,
	clientSecret string,
	oauthURL string,
	stepCAUrl string,
	fingerprint string,
	connectionAddr string,
) (string, string, error) {
	token, err := c.getOauthToken(ethAddress, privateKey, clientSecret, oauthURL)
	if err != nil {
		return "", "", fmt.Errorf("error getting token: %w", err)
	}
	c.Config.Logger.Info().Msgf("Token retrieved successfully: %s", token)

	cert, pk, err := c.signWeb3Certificate(token, connectionAddr, stepCAUrl, fingerprint)
	if err != nil {
		return "", "", fmt.Errorf("error creating certificate: %w", err)
	}
	c.Config.Logger.Info().Msg("Certificate created successfully!")

	return cert, pk, nil
}

func (c *CertLib) getOauthToken(ethAddress *common.Address, privateKey *ecdsa.PrivateKey, clientSecret string, oauthURL string) (string, error) {
	initParams := url.Values{}
	initParams.Set("domain", c.Config.Domain)
	initParams.Set("client_id", c.Config.ClientID)
	initParams.Set("response_type", c.Config.ResponseType)
	initParams.Set("scope", c.Config.Scope)
	initParams.Set("address", ethAddress.Hex())

	resp, err := c.Config.HTTPClient.PostForm(oauthURL+c.Config.GenerateChallengeURI, initParams)
	if err != nil {
		return "", fmt.Errorf("error generating challenge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error generating challenge: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	var challengeResponse ChallengeResponse
	if err := json.Unmarshal(body, &challengeResponse); err != nil {
		return "", fmt.Errorf("error unmarshalling response body: %w", err)
	}

	nonce := challengeResponse.Challenge
	c.Config.Logger.Debug().Msgf("Challenge generated: %s", nonce)

	signedChallenge, err := c.signChallenge(nonce, privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing challenge: %w", err)
	}

	submitParams := url.Values{}
	submitParams.Set("client_id", c.Config.ClientID)
	submitParams.Set("domain", c.Config.Domain)
	submitParams.Set("grant_type", c.Config.GrantType)
	submitParams.Set("state", challengeResponse.State)
	submitParams.Set("signature", signedChallenge)
	submitParams.Set("client_secret", clientSecret)

	resp, err = c.Config.HTTPClient.Post(oauthURL+c.Config.SubmitChallengeURI, "application/x-www-form-urlencoded", strings.NewReader(submitParams.Encode()))
	if err != nil {
		return "", fmt.Errorf("error submitting challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		challengeBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status code: %d, expected: %d, response body: %s", resp.StatusCode, http.StatusOK, string(challengeBody))
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("error unmarshalling response body: %w", err)
	}

	return tokenResp.AccessToken, nil
}

func (c *CertLib) signWeb3Certificate(token string, connectionAddr string, stepCAUrl string, fingerprint string) (string, string, error) {
	stepCa, err := ca.NewClient(stepCAUrl, ca.WithRootSHA256(fingerprint))
	if err != nil {
		return "", "", fmt.Errorf("error creating step CA client: %w", err)
	}

	req, pk, err := c.createSignRequest(token, connectionAddr)
	if err != nil {
		return "", "", fmt.Errorf("error creating sign request: %w", err)
	}

	certificate, err := stepCa.Sign(req)
	if err != nil {
		return "", "", fmt.Errorf("error signing certificate request: %w", err)
	}

	var certChainPem []byte
	for _, cert := range certificate.CertChainPEM {
		block := &pem.Block{Type: c.Config.CertificatePEMType, Bytes: cert.Raw}
		certChainPem = append(certChainPem, pem.EncodeToMemory(block)...)
	}

	// Marshal the private key into PKCS8 format
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return "", "", fmt.Errorf("error marshalling private key: %w", err)
	}

	// Encode the private key into PEM format
	pemBlock := &pem.Block{
		Type:  c.Config.PrivateKeyPEMType,
		Bytes: pkcs8Bytes,
	}
	privateKeyPem := pem.EncodeToMemory(pemBlock)

	return string(certChainPem), string(privateKeyPem), nil
}

func (c *CertLib) createSignRequest(ott string, connectionAddr string) (*api.SignRequest, crypto.PrivateKey, error) {
	token, err := jose.ParseSigned(ott)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing jwt '%s': %w", ott, err)
	}
	var claims authority.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, fmt.Errorf("error parsing claims from jwt: %w", err)
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key: %w", err)
	}

	dnsNames, ips, emails, uris := x509util.SplitSANs(claims.SANs)
	if claims.Email != "" {
		emails = append(emails, claims.Email)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: connectionAddr,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		URIs:               uris,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, pk)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate request: %w", err)
	}
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate request: %w", err)
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("error signing certificate request: %w", err)
	}
	return &api.SignRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: cr},
		OTT:    ott,
	}, pk, nil
}

func (c *CertLib) signChallenge(nonce string, privateKey *ecdsa.PrivateKey) (string, error) {
	message := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(nonce), nonce)
	keccak256Hash := cr.Keccak256Hash([]byte(message))
	signedMsg, err := cr.Sign(keccak256Hash[:], privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing message: %w", err)
	}
	signedMsg[64] += 27
	return "0x" + hex.EncodeToString(signedMsg), nil
}
