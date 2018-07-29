package qiniu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/qiniu/api.v7/auth/qbox"
)

const APIHost = "http://api.qiniu.com"

type Client struct {
	*qbox.Mac
}

func New(accessKey, secretKey string) *Client {
	return &Client{
		Mac: qbox.NewMac(accessKey, secretKey),
	}
}

func (c *Client) Request(method string, path string, body interface{}) (resData []byte,
	err error) {
	urlStr := fmt.Sprintf("%s%s", APIHost, path)
	reqData, _ := json.Marshal(body)
	req, reqErr := http.NewRequest(method, urlStr, bytes.NewReader(reqData))
	if reqErr != nil {
		err = reqErr
		return
	}

	accessToken, signErr := c.SignRequest(req)
	if signErr != nil {
		err = signErr
		return
	}

	req.Header.Add("Authorization", "QBox "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, respErr := http.DefaultClient.Do(req)
	if respErr != nil {
		err = respErr
		return
	}
	defer resp.Body.Close()

	resData, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		err = ioErr
		return
	}

	return
}

func (c *Client) GetDomainInfo(domain string) (*DomainInfo, error) {
	b, err := c.Request("GET", "/domain/"+domain, nil)
	if err != nil {
		return nil, err
	}
	info := &DomainInfo{}
	if err := json.Unmarshal(b, info); err != nil {
		return nil, err
	}
	if info.Code > 200 {
		return nil, fmt.Errorf("%d: %s", info.Code, info.Error)
	}
	return info, nil
}

func (c *Client) GetCertInfo(certID string) (*CertInfo, error) {
	b, err := c.Request("GET", "/sslcert/"+certID, nil)
	if err != nil {
		return nil, err
	}
	info := &CertInfo{}
	if err := json.Unmarshal(b, info); err != nil {
		return nil, err
	}
	if info.Code > 200 {
		return nil, fmt.Errorf("%d: %s", info.Code, info.Error)
	}
	return info, nil
}

func (c *Client) UploadCert(cert Cert) (*UploadCertResp, error) {
	b, err := c.Request("POST", "/sslcert", cert)
	if err != nil {
		return nil, err
	}
	resp := &UploadCertResp{}
	if err := json.Unmarshal(b, resp); err != nil {
		return nil, err
	}
	if resp.Code > 200 {
		return nil, fmt.Errorf("%d: %s", resp.Code, resp.Error)
	}
	return resp, nil
}

func (c *Client) UpdateHttpsConf(domain, certID string) (*CodeErr, error) {
	b, err := c.Request("PUT", "/domain/"+domain+"/httpsconf", HTTPSConf{
		CertID:     certID,
		ForceHttps: true,
	})
	if err != nil {
		return nil, err
	}
	fmt.Println(string(b))
	resp := &CodeErr{}
	if err := json.Unmarshal(b, resp); err != nil {
		return nil, err
	}
	if resp.Code > 200 {
		return nil, fmt.Errorf("%d: %s", resp.Code, resp.Error)
	}
	return resp, nil
}

func (c *Client) DeleteCert(certID string) (*CodeErr, error) {
	b, err := c.Request("DELETE", "/sslcert/"+certID, nil)
	if err != nil {
		return nil, err
	}
	resp := &CodeErr{}
	if err := json.Unmarshal(b, resp); err != nil {
		return nil, err
	}
	if resp.Code > 200 {
		return nil, fmt.Errorf("%d: %s", resp.Code, resp.Error)
	}
	return resp, nil
}

func (c *Client) DomainSSLize(domain, certID string) (*CodeErr, error) {
	b, err := c.Request("PUT", "/domain/"+domain+"/sslize", HTTPSConf{
		CertID:     certID,
		ForceHttps: true,
	})
	if err != nil {
		return nil, err
	}
	resp := &CodeErr{}
	if err := json.Unmarshal(b, resp); err != nil {
		return nil, err
	}
	if resp.Code > 200 {
		return nil, fmt.Errorf("%d: %s", resp.Code, resp.Error)
	}
	return resp, nil
}
