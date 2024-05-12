package gogrpctls

import (
	"os"

	"google.golang.org/grpc/credentials"
)

type CertManager interface {
	LoadServerCertificate() (credentials.TransportCredentials, error)
	LoadClientCredentials() (credentials.TransportCredentials, error)
}

func NewCertManager() CertManager {
	if _, exist := os.LookupEnv("ARN"); exist {
		return &AwsCertManager{}
	}

	return &SelfSignedCertManager{}
}
