package gogrpctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	awsCredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"google.golang.org/grpc/credentials"
	grpcCreds "google.golang.org/grpc/credentials"
)

func getAwsClient() (*acm.Client, error) {
	awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

	awscreds := awsCredentials.NewStaticCredentialsProvider(awsAccessKey, awsSecretKey, "")

	// Configurar la configuración con el provider de credenciales personalizado
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(awscreds),
	)

	if err != nil {
		return &acm.Client{}, err
	}

	return acm.NewFromConfig(cfg), err
}

type AwsCertManager struct {
}

func (cm *AwsCertManager) loadClientCredentials() (grpcCreds.TransportCredentials, error) {
	// var address string = "..."      // URL of the gRPC server

	client, err := getAwsClient()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	arn := os.Getenv("ARN")

	certificate, err := client.GetCertificate(context.Background(), &acm.GetCertificateInput{CertificateArn: &arn})
	if err != nil {
		log.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(*certificate.Certificate))

	creds := grpcCreds.NewClientTLSFromCert(pool, "")
	return creds, nil

}

func (cm *AwsCertManager) loadServerCertificate() (credentials.TransportCredentials, error) {
	acmClient, err := getAwsClient()

	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	// Obtener el certificado de ACM
	arn := os.Getenv("ARN")

	resp, err := acmClient.GetCertificate(context.TODO(), &acm.GetCertificateInput{
		CertificateArn: &arn,
	})
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{[]byte(*resp.Certificate)},
		PrivateKey:  nil, // Debes proporcionar la clave privada si está disponible
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}), nil
}
