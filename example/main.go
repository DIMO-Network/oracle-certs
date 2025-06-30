package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"log"
	"oracle-certs/certlib"
	"os"

	"github.com/ethereum/go-ethereum/common"
	cr "github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Generate a new wallet
	privateKey, ethAddress, errGen := generateWallet()
	if errGen != nil {
		log.Fatalf("Error generating wallet: %v", errGen)
	}

	// Load parameters from environment variables
	clientSecret := os.Getenv("CLIENT_SECRET")
	oauthURL := os.Getenv("OAUTH_URL")
	stepCAUrl := os.Getenv("STEP_CA_URL")
	fingerprint := os.Getenv("FINGERPRINT")
	connectionAddr := os.Getenv("CONNECTION_ADDR")

	if clientSecret == "" || oauthURL == "" || stepCAUrl == "" || fingerprint == "" || connectionAddr == "" {
		log.Fatal("Missing required environment variables")
	}

	// Create a new CertLib instance
	config := certlib.NewDefaultConfig()
	certLib := certlib.NewCertLib(config)

	// Request a certificate
	cert, pk, err := certLib.RequestCertificates(ethAddress, privateKey, clientSecret, oauthURL, stepCAUrl, fingerprint, connectionAddr)
	if err != nil {
		log.Fatalf("Error requesting certificate: %v", err)
	}

	// Print the certificate and private key
	log.Printf("Certificate:\n%s", cert)
	log.Printf("Private Key:\n%s", pk)

	// Create a TLS client configuration
	tlsConfig, err := createTLSClient(cert, pk)
	if err != nil {
		log.Fatalf("Error creating TLS client: %v", err)
	}

	fmt.Println("TLS client configuration created successfully:", tlsConfig)
}

func createTLSClient(certPEM, keyPEM string) (*tls.Config, error) {
	privateKey, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate and private key: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{privateKey},
	}, nil
}

func generateWallet() (*ecdsa.PrivateKey, *common.Address, error) {
	privateKey, err := cr.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	userAddr := cr.PubkeyToAddress(privateKey.PublicKey)
	return privateKey, &userAddr, nil
}
