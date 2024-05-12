package gogrpctls

import (
	"os"

	"google.golang.org/grpc/credentials"
)

type CertManager interface {
	loadServerCertificate() (credentials.TransportCredentials, error)
	loadClientCredentials() (credentials.TransportCredentials, error)
}

func NewCertManager() CertManager {
	if _, exist := os.LookupEnv("ARN"); exist {
		return &AwsCertManager{}
	}

	return &SelfSignedCertManager{}
}
