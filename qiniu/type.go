package qiniu

import (
	"strconv"
	"time"
)

type CodeErr struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}

type DomainInfo struct {
	CodeErr
	Name               string    `json:"name"`
	PareDomain         string    `json:"pareDomain"`
	Type               string    `json:"type"`
	Cname              string    `json:"cname"`
	TestURLPath        string    `json:"testURLPath"`
	Protocol           string    `json:"protocol"`
	Platform           string    `json:"platform"`
	GeoCover           string    `json:"geoCover"`
	QiniuPrivate       bool      `json:"qiniuPrivate"`
	OperationType      string    `json:"operationType"`
	OperatingState     string    `json:"operatingState"`
	OperatingStateDesc string    `json:"operatingStateDesc"`
	CreateAt           time.Time `json:"createAt"`
	ModifyAt           time.Time `json:"modifyAt"`
	HTTPS              struct {
		CertID     string `json:"certId"`
		ForceHTTPS bool   `json:"forceHttps"`
	} `json:"https"`
	CouldOperateBySelf bool   `json:"couldOperateBySelf"`
	RegisterNo         string `json:"registerNo"`
}

type Cert struct {
	Name       string `json:"name"`
	CommonName string `json:"common_name"`
	CA         string `json:"ca"`
	Pri        string `json:"pri"`
}

type UploadCertResp struct {
	CodeErr
	CertID string `json:"certID"`
}

type CertInfo struct {
	CodeErr
	Cert struct {
		CertID           string    `json:"certid"`
		Name             string    `json:"name"`
		UID              int       `json:"uid"`
		CommonName       string    `json:"common_name"`
		DNSNames         []string  `json:"dnsnames"`
		CreateTime       TimeStamp `json:"create_time"`
		NotBefore        TimeStamp `json:"not_before"`
		NotAfter         TimeStamp `json:"not_after"`
		OrderID          string    `json:"orderid"`
		ProductShortName string    `json:"product_short_name"`
		ProductType      string    `json:"product_type"`
		Encrypt          string    `json:"encrypt"`
		EncryptParameter string    `json:"encryptParameter"`
		Enable           bool      `json:"enable"`
		Ca               string    `json:"ca"`
		Pri              string    `json:"pri"`
	} `json:"cert"`
}

type TimeStamp struct {
	time.Time
}

func (t *TimeStamp) UnmarshalJSON(b []byte) error {
	i, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return err
	}
	t.Time = time.Unix(i, 0)
	return nil
}

type HTTPSConf struct {
	CertID     string `json:"certid"`
	ForceHttps bool   `json:"forceHttps"`
}
