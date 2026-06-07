package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertManager 证书管理器
type CertManager struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	caTLSCert tls.Certificate
	cache     sync.Map // domain -> tls.Certificate
	certDir   string
	logger    *slog.Logger
}

// NewCertManager 创建证书管理器，自动生成或加载CA证书
func NewCertManager(certDir string, logger *slog.Logger) (*CertManager, error) {
	cm := &CertManager{
		certDir: certDir,
		logger:  logger,
	}

	caCertPath := filepath.Join(certDir, "ca.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")

	// 尝试加载已有CA证书
	if cm.loadCA(caCertPath, caKeyPath) {
		logger.Info("loaded existing CA certificate", "path", caCertPath)
		return cm, nil
	}

	// 生成新的CA证书
	if err := cm.generateCA(); err != nil {
		return nil, fmt.Errorf("generate CA failed: %w", err)
	}

	// 保存CA证书到文件
	if err := cm.saveCA(caCertPath, caKeyPath); err != nil {
		return nil, fmt.Errorf("save CA failed: %w", err)
	}

	logger.Info("generated new CA certificate", "path", caCertPath)
	return cm, nil
}

// generateCA 生成CA根证书
func (cm *CertManager) generateCA() error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"XRay-Distribute"},
			OrganizationalUnit: []string{"Mirror Proxy CA"},
			CommonName:         "XRay-Distribute Root CA",
			Country:            []string{"CN"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10年
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}

	cm.caCert = cert
	cm.caKey = key
	cm.caTLSCert = tlsCert

	return nil
}

// loadCA 加载已有CA证书
func (cm *CertManager) loadCA(certPath, keyPath string) bool {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return false
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		cm.logger.Warn("load CA keypair failed", "error", err)
		return false
	}

	if tlsCert.Leaf == nil {
		tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	}

	cm.caTLSCert = tlsCert
	cm.caCert = tlsCert.Leaf

	// 提取私钥
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return false
	}
	cm.caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// 尝试PKCS8
		k, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return false
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return false
		}
		cm.caKey = rsaKey
	}

	return true
}

// saveCA 保存CA证书到文件
func (cm *CertManager) saveCA(certPath, keyPath string) error {
	os.MkdirAll(filepath.Dir(certPath), 0755)

	// 保存证书
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.caCert.Raw,
	})

	// 保存私钥
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cm.caKey),
	})

	return nil
}

// GetCACertPEM 获取CA证书PEM格式（供下载）
func (cm *CertManager) GetCACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.caCert.Raw,
	})
}

// GetCACertDER 获取CA证书DER格式（供手机导入）
func (cm *CertManager) GetCACertDER() []byte {
	return cm.caCert.Raw
}

// GetTLSConfig 获取动态签发证书的TLS配置
func (cm *CertManager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cm.GetCertForHost(hello.ServerName)
		},
		MinVersion: tls.VersionTLS12,
	}
}

// GetCertForHost 为指定域名动态签发证书
func (cm *CertManager) GetCertForHost(host string) (*tls.Certificate, error) {
	// 查缓存
	if cached, ok := cm.cache.Load(host); ok {
		cert := cached.(tls.Certificate)
		// 检查是否过期
		if cert.Leaf != nil && time.Now().Before(cert.Leaf.NotAfter) {
			return &cert, nil
		}
	}

	// 生成新证书
	cert, err := cm.signCert(host)
	if err != nil {
		return nil, err
	}

	// 缓存
	cm.cache.Store(host, *cert)
	return cert, nil
}

// signCert 为域名签发证书
func (cm *CertManager) signCert(host string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"XRay-Distribute"},
			CommonName:   host,
		},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1年
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	// 支持通配符
	if host != "" && host[0] != '*' {
		template.DNSNames = append(template.DNSNames, "*."+host)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &key.PublicKey, cm.caKey)
	if err != nil {
		return nil, err
	}

	leaf, _ := x509.ParseCertificate(certDER)

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, cm.caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}

	return tlsCert, nil
}
