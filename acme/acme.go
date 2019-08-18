package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns"
	"github.com/go-acme/lego/v3/registration"
)

type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u User) GetEmail() string {
	return u.Email
}

func (u User) GetRegistration() *registration.Resource {
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
	defer func() {
		if err := certOut.Close(); err != nil {
			log.Println("close", file, "error: ", err)
		}
	}()

	err = pem.Encode(certOut, &pemKey)
	if err != nil {
		return nil, err
	}

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

func GetAcmeClient(email string) (*lego.Client, error) {
	user := User{Email: email}

	var client *lego.Client
	var err error
	var reg *registration.Resource

	privateKeyPath := path.Join(os.TempDir(), "qiniu-auto-cert.privateKey")
	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		key, err := generatePrivateKey(privateKeyPath)
		if err != nil {
			return nil, err
		}
		user.key = key

		client, err = lego.NewClient(lego.NewConfig(user))
		if err != nil {
			return nil, err
		}

		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
	} else {
		user.key = key
		client, err = lego.NewClient(lego.NewConfig(user))
		if err != nil {
			return nil, err
		}

		reg, err = client.Registration.ResolveAccountByKey()
		if err != nil {
			return nil, err
		}
	}

	user.Registration = reg

	provider, err := dns.NewDNSChallengeProviderByName(os.Getenv("DNS_PROVIDER"))
	if err != nil {
		return nil, err
	}
	client.Challenge.Remove(challenge.HTTP01)
	client.Challenge.Remove(challenge.TLSALPN01)
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func ObtainCert(email, domain string) (*certificate.Resource, error) {
	client, err := GetAcmeClient(email)
	if err != nil {
		return nil, err
	}
	cert, err := loadCertResource(domain)
	if err != nil {
		return obtainNewCert(client, domain)
	}

	cert, err = client.Certificate.Renew(*cert, false, false)
	if err != nil {
		return obtainNewCert(client, domain)
	}
	if err := saveCertInfo(domain, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func obtainNewCert(client *lego.Client, domain string) (*certificate.Resource, error) {
	cert, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{domain},
	})
	if err != nil {
		return nil, err
	}
	if err := saveCertInfo(domain, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func saveCertInfo(domain string, cert *certificate.Resource) error {
	metaPath := path.Join(os.TempDir(), "qiniu-auto-cert-"+domain+".json")
	privateKeyPath := path.Join(os.TempDir(), "qiniu-auto-cert-"+domain+".key")
	certPath := path.Join(os.TempDir(), "qiniu-auto-cert-"+domain+".crt")
	metaData, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(metaPath, metaData, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(privateKeyPath, cert.PrivateKey, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certPath, cert.Certificate, 0600)
	if err != nil {
		return err
	}
	return nil
}

func loadCertResource(domain string) (*certificate.Resource, error) {
	metaPath := path.Join(os.TempDir(), "qiniu-auto-cert-"+domain+".json")
	privateKeyPath := path.Join(os.TempDir(), "qiniu-auto-cert-"+domain+".key")
	certPath := path.Join(os.TempDir(), "qiniu-auto-cert-"+domain+".crt")
	cert := new(certificate.Resource)
	meta, err := ioutil.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(meta, cert); err != nil {
		return nil, err
	}
	privateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	cert.PrivateKey = privateKey
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	cert.Certificate = certData
	return cert, nil
}
