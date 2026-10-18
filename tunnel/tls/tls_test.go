package tls

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/test/util"
	"github.com/p4gefau1t/trojan-go/tunnel/freedom"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
)

var rsa2048Cert = `
-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIUVtYUVuaTEBRqmIbY6X8cfIVT6YcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAxODA0MjgwNloYDzIxMjYw
OTI0MDQyODA2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDljT9zsgNXhf1AST47Sjhcae8L6XMnR/56ma3TbghX
fRqsNLsP2zTfcNEIA53oSwT5ZjBgLblxUWZ8y12yjAYqLYavz7woGCo7eD6O8izo
un81PA1RTfMExdi6IUv826fW9XKJbdXz/u7w+3E9Wzt+Frn2mB35+1W7mQ5X+9E3
KNOZkJkA9ofHAzCPZ0F6UzcUQqTLw0sK1T8QgoWsfhVTu/OKZXl7oANmRcl+CAHW
qYAW+gAmAl6i/4snTeuQcErMOdlzOgIVz2DgAwGxWy+EAM3QhzFLLTZuY7b7Wn2B
9yqR+6SgalhgMGFu6xTxVwuAe5h2Jn4OQpIt5beOpT3TAgMBAAGjgZYwgZMwHQYD
VR0OBBYEFA0BySmoOyQHpLkgMYsebe91hjlEMB8GA1UdIwQYMBaAFA0BySmoOyQH
pLkgMYsebe91hjlEMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxo
b3N0MAsGA1UdDwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DQYJKoZIhvcNAQELBQADggEBAB/+U/HTEy83adbxV7HYV50nHLhuy3gwXURj2bXT
lABHppvFIKrzICDnLFrBXM9Dy7GWozzypELWAoP+vBf1dw2DcIVZ+2ODb2Kovugn
HCZ/xC4kiP980PxxV+1FxPpb3+oAJ/Bxq5Lb02SnzDnEo3u21z3UDGpohueQFN1N
NCxIWwDgdYWY8tufhXd8V0M3HRLs+YWXBqx1HvRjHu0yO0ZD9/OxG779t1z8gK8u
rZ7Q0KHAbYM5FxawbLqLSCOqYC/l7CnqLgMw8i6SpHgaVUnMSqaADn+Aw1rJ5kap
g+0IimUm9I7Zc16Hb1tpGq+STdSffjgb+fcOKs9j+48m7qI=
-----END CERTIFICATE-----
`

var rsa2048Key = `
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDljT9zsgNXhf1A
ST47Sjhcae8L6XMnR/56ma3TbghXfRqsNLsP2zTfcNEIA53oSwT5ZjBgLblxUWZ8
y12yjAYqLYavz7woGCo7eD6O8izoun81PA1RTfMExdi6IUv826fW9XKJbdXz/u7w
+3E9Wzt+Frn2mB35+1W7mQ5X+9E3KNOZkJkA9ofHAzCPZ0F6UzcUQqTLw0sK1T8Q
goWsfhVTu/OKZXl7oANmRcl+CAHWqYAW+gAmAl6i/4snTeuQcErMOdlzOgIVz2Dg
AwGxWy+EAM3QhzFLLTZuY7b7Wn2B9yqR+6SgalhgMGFu6xTxVwuAe5h2Jn4OQpIt
5beOpT3TAgMBAAECggEATvm7GF9o1e5j1H++eOCOpoDNvP/q3dtfmqePzduf5BXH
HPMhXpGwzaT/Ta4M4FQbGIEHaLeigvGZ/JptGJYjMtSp74fdeL/jm8VBZKW+PK2Z
QWPxQwU59GzrJRJ6lbqusn6MkuqmfwU5CNDBQ3ZFcBp6jXQFcDF/7AR7ElsxPjPX
MItJU2DWD7Png5TMJELtoEXAnZDd8EUAuCfdt6uPSv2cApFRViPU1L74j/nS8jus
bEr6kdALJBOappaZZoqvaHNtHmK3HuFzXXiEf6WZXVnOpONX+PZO0py1RKrRyWTZ
IZXNrMGci5XtqcTLI6pNKTFHS+il1tCBDShmKuIi6QKBgQD87Slz1X3P7zrUYLAb
GuSitelc0kQ1BI5drcPH+cRX/VqvuQD6VIRvuGZu+oH9q9gHg4rQ7Ot2OtgRhUrp
rDczqlj2tMgFhD3vS24oS41BjSesctILceSq/0Br6n1KPyKxllgFY3IcUTpxQOn/
rL1UVf8zUB+th4tcZiFtuoS7eQKBgQDoV15r2Gwa0EiqwbWr3sURh9kqggJXeNTw
fAdvackYlmB1cvh3XsYGuITX2tAYV6LT6Xl+yvkpULHHamXgYQ6iJCJSljWRNitO
xUA5VG6V95WO5lKMGnZgcxPJCDkKrhxOz1wrZ+r5wXFfvW/4mZ5SSZWuH34+EXYD
Kcjk89ckqwKBgQDnHxUFC27HRxWcIqpqal3JLbAMqPu48uvhQLsqDtvTh+mJr+Xr
2rWWnYvFF9cXZiOnYhXEqurThBwTjpkRBNUAukZHUpWBLQGnnGcSHU/8Oa+qTtYP
rUjG1S8aLhHFegILA5Z1fhU1OSjNewMZJtFvspHcYvg/ix/XFGCxs4I9CQKBgQDn
osM2DcypZuIrq3gt46jhc2ilInynLIZPQ7g98V9VrgZ40ai5ibkv1iJK+ZHh0u05
DFneeQmzkQnM4Fy1OM5YBGJbp/m7zh+bJriC75RY2z81+pZtq6w9OD2PfS0xYqhC
QiWH+NChM6SOaNULKkxXiZk6wZcg1lOrj6sD576khQKBgQDwBDWVdxRmPCyGq21K
vJv+crYIy9jErjkKD95KuPkIRdVkjsgw6RxjCDeVErZ6B5e3NqVzD8stwiwHjBQt
0e75yKpfd9W86pqI9t5ZeDjBqb1k9bZt9xOjNkMgdbVgbM0KJWoa1lnyoOZOn2qe
a+PAwyfhp78ND7IoUuoGX21nYA==
-----END PRIVATE KEY-----
`

var eccCert = `
-----BEGIN CERTIFICATE-----
MIIB4DCCAYagAwIBAgIUeH5RUYFRoHuHIdT77z45yjtzXi8wCgYIKoZIzj0EAwIw
ITELMAkGA1UEBhMCQ04xEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0yNjEwMTgwNDI4
MDdaGA8yMTI2MDkyNDA0MjgwN1owITELMAkGA1UEBhMCQ04xEjAQBgNVBAMMCWxv
Y2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABErZmUDHEZDdZXgjUlq3
2pJd5Jr4Jr/8URHWhyYPC0eIrABBORJTeccC0Pmw6C4UJeK3Dcqpu1/++sfBhD/J
+sWjgZkwgZYwHQYDVR0OBBYEFIWsfeftSq1Eaq7qiniv3fgEHJTAMB8GA1UdIwQY
MBaAFIWsfeftSq1Eaq7qiniv3fgEHJTAMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0R
BA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIgFbtsxXylOL+nL5V3cdpm
WnohOZENz6up44xKU49t0P8CIQD0hmVR/gGTjSSBxa/DNqxZvo779Stirx0w2fiE
taYWlw==
-----END CERTIFICATE-----
`

var eccKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII5YGc+PoVV8Xn1nJlWjJc00KEGPeZKu5npjhh2VBZnIoAoGCCqGSM49
AwEHoUQDQgAEStmZQMcRkN1leCNSWrfakl3kmvgmv/xREdaHJg8LR4isAEE5ElN5
xwLQ+bDoLhQl4rcNyqm7X/76x8GEP8n6xQ==
-----END EC PRIVATE KEY-----
`

func TestDefaultTLSRSA2048(t *testing.T) {
	os.WriteFile("server-rsa2048.crt", []byte(rsa2048Cert), 0o777)
	os.WriteFile("server-rsa2048.key", []byte(rsa2048Key), 0o777)
	serverCfg := &Config{
		TLS: TLSConfig{
			VerifyHostName: true,
			CertCheckRate:  1,
			KeyPath:        "server-rsa2048.key",
			CertPath:       "server-rsa2048.crt",
		},
	}
	clientCfg := &Config{
		TLS: TLSConfig{
			Verify:      false,
			SNI:         "localhost",
			Fingerprint: "",
		},
	}
	sctx := config.WithConfig(context.Background(), Name, serverCfg)
	cctx := config.WithConfig(context.Background(), Name, clientCfg)

	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx := config.WithConfig(context.Background(), transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)
	common.Must(err)
	s, err := NewServer(sctx, tcpServer)
	common.Must(err)
	c, err := NewClient(cctx, tcpClient)
	common.Must(err)

	wg := sync.WaitGroup{}
	wg.Add(1)
	var conn1, conn2 net.Conn
	go func() {
		conn2, err = s.AcceptConn(nil)
		common.Must(err)
		wg.Done()
	}()
	conn1, err = c.DialConn(nil, nil)
	common.Must(err)

	common.Must2(conn1.Write([]byte("12345678\r\n")))
	wg.Wait()
	buf := [10]byte{}
	conn2.Read(buf[:])
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}
	conn1.Close()
	conn2.Close()
}

func TestDefaultTLSECC(t *testing.T) {
	os.WriteFile("server-ecc.crt", []byte(eccCert), 0o777)
	os.WriteFile("server-ecc.key", []byte(eccKey), 0o777)
	serverCfg := &Config{
		TLS: TLSConfig{
			VerifyHostName: true,
			CertCheckRate:  1,
			KeyPath:        "server-ecc.key",
			CertPath:       "server-ecc.crt",
		},
	}
	clientCfg := &Config{
		TLS: TLSConfig{
			Verify:      false,
			SNI:         "localhost",
			Fingerprint: "",
		},
	}
	sctx := config.WithConfig(context.Background(), Name, serverCfg)
	cctx := config.WithConfig(context.Background(), Name, clientCfg)

	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx := config.WithConfig(context.Background(), transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)
	common.Must(err)
	s, err := NewServer(sctx, tcpServer)
	common.Must(err)
	c, err := NewClient(cctx, tcpClient)
	common.Must(err)

	wg := sync.WaitGroup{}
	wg.Add(1)
	var conn1, conn2 net.Conn
	go func() {
		conn2, err = s.AcceptConn(nil)
		common.Must(err)
		wg.Done()
	}()
	conn1, err = c.DialConn(nil, nil)
	common.Must(err)

	common.Must2(conn1.Write([]byte("12345678\r\n")))
	wg.Wait()
	buf := [10]byte{}
	conn2.Read(buf[:])
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}
	conn1.Close()
	conn2.Close()
}

func TestUTLSRSA2048(t *testing.T) {
	os.WriteFile("server-rsa2048.crt", []byte(rsa2048Cert), 0o777)
	os.WriteFile("server-rsa2048.key", []byte(rsa2048Key), 0o777)
	fingerprints := []string{
		"chrome",
		"firefox",
		"ios",
	}
	for _, s := range fingerprints {
		serverCfg := &Config{
			TLS: TLSConfig{
				CertCheckRate: 1,
				KeyPath:       "server-rsa2048.key",
				CertPath:      "server-rsa2048.crt",
			},
		}
		clientCfg := &Config{
			TLS: TLSConfig{
				Verify:      false,
				SNI:         "localhost",
				Fingerprint: s,
			},
		}
		sctx := config.WithConfig(context.Background(), Name, serverCfg)
		cctx := config.WithConfig(context.Background(), Name, clientCfg)

		port := common.PickPort("tcp", "127.0.0.1")
		transportConfig := &transport.Config{
			LocalHost:  "127.0.0.1",
			LocalPort:  port,
			RemoteHost: "127.0.0.1",
			RemotePort: port,
		}
		ctx := config.WithConfig(context.Background(), transport.Name, transportConfig)
		ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
		tcpClient, err := transport.NewClient(ctx, nil)
		common.Must(err)
		tcpServer, err := transport.NewServer(ctx, nil)
		common.Must(err)

		s, err := NewServer(sctx, tcpServer)
		common.Must(err)
		c, err := NewClient(cctx, tcpClient)
		common.Must(err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		var conn1, conn2 net.Conn
		go func() {
			conn2, err = s.AcceptConn(nil)
			common.Must(err)
			wg.Done()
		}()
		conn1, err = c.DialConn(nil, nil)
		common.Must(err)

		common.Must2(conn1.Write([]byte("12345678\r\n")))
		wg.Wait()
		buf := [10]byte{}
		conn2.Read(buf[:])
		if !util.CheckConn(conn1, conn2) {
			t.Fail()
		}
		conn1.Close()
		conn2.Close()
		s.Close()
		c.Close()
	}
}

func TestUTLSECC(t *testing.T) {
	os.WriteFile("server-ecc.crt", []byte(eccCert), 0o777)
	os.WriteFile("server-ecc.key", []byte(eccKey), 0o777)
	fingerprints := []string{
		"chrome",
		"firefox",
		"ios",
	}
	for _, s := range fingerprints {
		serverCfg := &Config{
			TLS: TLSConfig{
				CertCheckRate: 1,
				KeyPath:       "server-ecc.key",
				CertPath:      "server-ecc.crt",
			},
		}
		clientCfg := &Config{
			TLS: TLSConfig{
				Verify:      false,
				SNI:         "localhost",
				Fingerprint: s,
			},
		}
		sctx := config.WithConfig(context.Background(), Name, serverCfg)
		cctx := config.WithConfig(context.Background(), Name, clientCfg)

		port := common.PickPort("tcp", "127.0.0.1")
		transportConfig := &transport.Config{
			LocalHost:  "127.0.0.1",
			LocalPort:  port,
			RemoteHost: "127.0.0.1",
			RemotePort: port,
		}
		ctx := config.WithConfig(context.Background(), transport.Name, transportConfig)
		ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
		tcpClient, err := transport.NewClient(ctx, nil)
		common.Must(err)
		tcpServer, err := transport.NewServer(ctx, nil)
		common.Must(err)

		s, err := NewServer(sctx, tcpServer)
		common.Must(err)
		c, err := NewClient(cctx, tcpClient)
		common.Must(err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		var conn1, conn2 net.Conn
		go func() {
			conn2, err = s.AcceptConn(nil)
			common.Must(err)
			wg.Done()
		}()
		conn1, err = c.DialConn(nil, nil)
		common.Must(err)

		common.Must2(conn1.Write([]byte("12345678\r\n")))
		wg.Wait()
		buf := [10]byte{}
		conn2.Read(buf[:])
		if !util.CheckConn(conn1, conn2) {
			t.Fail()
		}
		conn1.Close()
		conn2.Close()
		s.Close()
		c.Close()
	}
}

func TestMatch(t *testing.T) {
	if !isDomainNameMatched("*.google.com", "www.google.com") {
		t.Fail()
	}

	if isDomainNameMatched("*.google.com", "google.com") {
		t.Fail()
	}

	if !isDomainNameMatched("localhost", "localhost") {
		t.Fail()
	}
}
