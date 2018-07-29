package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/jqs7/qiniu-auto-cert/acme"
	"github.com/jqs7/qiniu-auto-cert/qiniu"

	"github.com/pkg/errors"
)

func main() {
	qnClient := qiniu.New(
		os.Getenv("QINIU_ACCESSKEY"),
		os.Getenv("QINIU_SECRETKEY"),
	)
	Domain := os.Args[1]
	Email := os.Args[2]
	if err := autoCert(qnClient, Domain, Email); err != nil {
		log.Println(err)
	}
	for range time.Tick(time.Hour * 3) {
		if err := autoCert(qnClient, Domain, Email); err != nil {
			log.Println(err)
		}
	}
}

func autoCert(qnClient *qiniu.Client, Domain, Email string) error {
	domainInfo, err := qnClient.GetDomainInfo(Domain)
	if err != nil {
		log.Fatalln(err)
	}
	if domainInfo.HTTPS.CertID != "" {
		info, err := qnClient.GetCertInfo(domainInfo.HTTPS.CertID)
		if err != nil {
			return errors.WithMessage(err, "get cert info failed")
		}
		if time.Until(info.Cert.NotAfter.Time) > time.Hour*24*7 {
			return nil
		}
		cert, err := acme.ObtainCert(Email, Domain)
		if err != nil {
			return errors.WithMessage(err, "obtain cert failed")
		}
		upload, err := qnClient.UploadCert(qiniu.Cert{
			Name:       strings.Split(Domain, ".")[0],
			CommonName: Domain,
			CA:         string(cert.Certificate),
			Pri:        string(cert.PrivateKey),
		})
		if err != nil {
			return errors.WithMessage(err, "upload cert failed")
		}
		_, err = qnClient.UpdateHttpsConf(Domain, upload.CertID)
		if err != nil {
			return errors.WithMessage(err, "update domain certID failed")
		}
		_, err = qnClient.DeleteCert(domainInfo.HTTPS.CertID)
		return errors.WithMessage(err, "delete cert failed")
	}
	cert, err := acme.ObtainCert(Email, Domain)
	if err != nil {
		return errors.WithMessage(err, "obtain cert failed")
	}
	upload, err := qnClient.UploadCert(qiniu.Cert{
		Name:       strings.Split(Domain, ".")[0],
		CommonName: Domain,
		CA:         string(cert.Certificate),
		Pri:        string(cert.PrivateKey),
	})
	if err != nil {
		return errors.WithMessage(err, "upload cert failed")
	}
	_, err = qnClient.DomainSSLize(Domain, upload.CertID)
	return errors.WithMessage(err, "sslize domain failed")
}
