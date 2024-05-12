package gogrpctls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"google.golang.org/grpc/credentials"
)

type SelfSignedCertManager struct {
}

func GetModuleDir() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get module directory")
	}

	absPath, err := filepath.Abs(filename)
	return absPath, err
}

func (cm *SelfSignedCertManager) LoadServerCertificate() (credentials.TransportCredentials, error) {
	// Load server's certificate and private key
	currentDir, err := GetModuleDir()
	if err != nil {
		return nil, err
	}

	fmt.Println(currentDir)

	serverCertPath := currentDir + "../../cert/server-cert.pem"
	serverKeyPath := currentDir + "../../cert/server-key.pem"

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	return credentials.NewTLS(config), nil
}

func (cm *SelfSignedCertManager) LoadClientCredentials() (credentials.TransportCredentials, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Construir la ruta absoluta a los certificados
	caCertPath := currentDir + "../../cert/ca-cert.pem"
	// Load certificate of the CA who signed server's certificate
	pemServerCA, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs: certPool,
	}

	return credentials.NewTLS(config), nil
}
