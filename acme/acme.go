package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns"
)

const CADirURL = "https://acme-v02.api.letsencrypt.org/directory"

type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u User) GetEmail() string {
	return u.Email
}
func (u User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
func generatePrivateKey(file string) (crypto.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pemKey := pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}

	pem.Encode(certOut, &pemKey)
	certOut.Close()

	return privateKey, nil
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

func GetAcmeClient(email string) (*acme.Client, error) {
	user := User{Email: email}

	var client *acme.Client
	var err error
	var reg *acme.RegistrationResource

	key, err := loadPrivateKey(path.Join(os.TempDir(), "privateKey"))
	if err != nil {
		key, err := generatePrivateKey(path.Join(os.TempDir(), "privateKey"))
		if err != nil {
			return nil, err
		}
		user.key = key

		client, err = acme.NewClient(CADirURL, &user, acme.RSA2048)
		if err != nil {
			return nil, err
		}

		reg, err = client.Register(true)
		if err != nil {
			return nil, err
		}
	} else {
		user.key = key
		client, err = acme.NewClient(CADirURL, &user, acme.RSA2048)
		if err != nil {
			return nil, err
		}

		reg, err = client.ResolveAccountByKey()
		if err != nil {
			return nil, err
		}
	}

	user.Registration = reg
	client.SetHTTPAddress(":5002")
	client.SetTLSAddress(":5001")

	provider, err := dns.NewDNSChallengeProviderByName(os.Getenv("DNS_PROVIDER"))
	if err != nil {
		return nil, err
	}
	client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSALPN01})
	err = client.SetChallengeProvider(acme.DNS01, provider)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func ObtainCert(email, domain string) (*acme.CertificateResource, error) {
	client, err := GetAcmeClient(email)
	if err != nil {
		return nil, err
	}
	return client.ObtainCertificate([]string{domain}, false, nil, false)
}
