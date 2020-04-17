package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/1990kawa/mqtt-benchmark/configs"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type TLSInfo struct {
	Verify   bool   `yaml:"verify"`
	CaFile   string `yaml:"caFile"`
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

type TLSConfig struct {
	Worker  int     `json:"workerNum"`
	TlsPort string  `json:"tlsPort"`
	TlsHost string  `json:"tlsHost"`
	TlsInfo TLSInfo `json:"tlsInfo"`
}

func NewTLSConfig() (*tls.Config, error) {
	if err := configs.Init(); err != nil {
		log.Print(fmt.Errorf("error config init: %v", zap.Error(err)))
		return nil, err
	}
	var tlsConfig TLSConfig
	err := viper.Unmarshal(&tlsConfig)
	if err != nil {
		log.Print(fmt.Errorf("error config Unmarshal: %v", zap.Error(err)))
		return nil, err
	}
	tlsInfo := tlsConfig.TlsInfo

	cert, err := tls.LoadX509KeyPair(tlsInfo.CertFile, tlsInfo.KeyFile)
	if err != nil {
		log.Print(fmt.Errorf("error paring X509 certificate/key pair: %v", zap.Error(err)))
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Print(fmt.Errorf("error parsing certificate: %v", zap.Error(err)))
		return nil, err
	}

	mqttConfig := tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	if tlsInfo.CaFile != "" {
		rootPEM, err := ioutil.ReadFile(tlsInfo.CaFile)
		if err != nil || rootPEM == nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM([]byte(rootPEM))
		if !ok {
			log.Print(fmt.Errorf("failed to parse root ca certificate"))
			return nil, err
		}
		mqttConfig.ClientCAs = pool
	}

	return &mqttConfig, nil
}
