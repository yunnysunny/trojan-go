package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/statistic/memory"
)

func TestServerAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})
	port := common.PickPort("tcp", "127.0.0.1")
	ctx = config.WithConfig(ctx, Name, &Config{
		APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
		},
	})
	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go RunServerAPI(ctx, auth)
	time.Sleep(time.Second * 3)
	common.Must(auth.AddUser("hash1234"))
	_, user := auth.AuthUser("hash1234")
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream1, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	for {
		resp, err := stream1.Recv()
		if err != nil {
			break
		}
		fmt.Println(resp.Status.User.Hash)
		if resp.Status.User.Hash != "hash1234" {
			t.Fail()
		}
		fmt.Println(resp.Status.SpeedCurrent)
		fmt.Println(resp.Status.SpeedLimit)
	}
	stream1.CloseSend()
	user.AddTraffic(1234, 5678)
	time.Sleep(time.Second * 1)
	stream2, err := server.GetUsers(ctx)
	common.Must(err)
	stream2.Send(&GetUsersRequest{
		User: &User{
			Hash: "hash1234",
		},
	})
	resp2, err := stream2.Recv()
	common.Must(err)
	if resp2.Status.TrafficTotal.DownloadTraffic != 1234 || resp2.Status.TrafficTotal.UploadTraffic != 5678 {
		t.Fatal("wrong traffic")
	}

	stream3, err := server.SetUsers(ctx)
	common.Must(err)
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "hash1234",
			},
		},
		Operation: SetUsersRequest_Delete,
	})
	resp3, err := stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("user not exists")
	}
	valid, _ := auth.AuthUser("hash1234")
	if valid {
		t.Fatal("failed to auth")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "newhash",
			},
		},
		Operation: SetUsersRequest_Add,
	})
	resp3, err = stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("failed to read")
	}
	valid, user = auth.AuthUser("newhash")
	if !valid {
		t.Fatal("failed to auth 2")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "newhash",
			},
			SpeedLimit: &Speed{
				DownloadSpeed: 5000,
				UploadSpeed:   3000,
			},
			TrafficTotal: &Traffic{
				DownloadTraffic: 1,
				UploadTraffic:   1,
			},
		},
		Operation: SetUsersRequest_Modify,
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddTraffic(200, 0)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddTraffic(0, 300)
		}
	}()
	time.Sleep(time.Second * 3)
	for i := 0; i < 3; i++ {
		stream2.Send(&GetUsersRequest{
			User: &User{
				Hash: "newhash",
			},
		})
		resp2, err = stream2.Recv()
		common.Must(err)
		fmt.Println(resp2.Status.SpeedCurrent)
		fmt.Println(resp2.Status.SpeedLimit)
		time.Sleep(time.Second)
	}
	stream2.CloseSend()
	cancel()
}

func TestTLSRSA(t *testing.T) {
	port := common.PickPort("tcp", "127.0.0.1")
	cfg := &Config{
		API: APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
			SSL: SSLConfig{
				Enabled:        true,
				CertPath:       "server-rsa2048.crt",
				KeyPath:        "server-rsa2048.key",
				VerifyClient:   false,
				ClientCertPath: []string{"client-rsa2048.crt"},
			},
		},
	}

	ctx := config.WithConfig(context.Background(), Name, cfg)
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})

	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go func() {
		common.Must(RunServerAPI(ctx, auth))
	}()
	time.Sleep(time.Second)
	pool := x509.NewCertPool()
	certBytes, err := os.ReadFile("server-rsa2048.crt")
	common.Must(err)
	pool.AppendCertsFromPEM(certBytes)

	certificate, err := tls.LoadX509KeyPair("client-rsa2048.crt", "client-rsa2048.key")
	common.Must(err)
	creds := credentials.NewTLS(&tls.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
	})
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(creds))
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	stream.CloseSend()
	conn.Close()
}

func TestTLSECC(t *testing.T) {
	port := common.PickPort("tcp", "127.0.0.1")
	cfg := &Config{
		API: APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
			SSL: SSLConfig{
				Enabled:        true,
				CertPath:       "server-ecc.crt",
				KeyPath:        "server-ecc.key",
				VerifyClient:   false,
				ClientCertPath: []string{"client-ecc.crt"},
			},
		},
	}

	ctx := config.WithConfig(context.Background(), Name, cfg)
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})

	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go func() {
		common.Must(RunServerAPI(ctx, auth))
	}()
	time.Sleep(time.Second)
	pool := x509.NewCertPool()
	certBytes, err := os.ReadFile("server-ecc.crt")
	common.Must(err)
	pool.AppendCertsFromPEM(certBytes)

	certificate, err := tls.LoadX509KeyPair("client-ecc.crt", "client-ecc.key")
	common.Must(err)
	creds := credentials.NewTLS(&tls.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
	})
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(creds))
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	stream.CloseSend()
	conn.Close()
}

var serverRSA2048Cert = `
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

var serverRSA2048Key = `
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

var clientRSA2048Cert = `
-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIUZ8LQRh1v2B1D4+NQb4xlmuFsaaowDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAxODA0MjgwN1oYDzIxMjYw
OTI0MDQyODA3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCfF/E6bOzzqkErSR3Sh54EnOcZBHU6yRkU8A00NakS
CCoTQYrjLCteTPVow7ghBgjzxnl+5GNAgARFm/yv3ashueLlc+B5VJ15jgbvB4hx
hYVlngptlpwTMF1mZfmZgC/YFEW8GFT5umRDf6itYlRHC43JMq/bJ1ZPse80su/5
IvXKd4lSBv/ef05oWNqmAaeqtE7eLhdMZxk2ZcFZrHwVyZDAI99TuFpquMQ4mrNN
ZFt391a4YroURl7fWOYf2HHM1IHOXb6FedukOMUf/TLOIHxV18fEyE6YERfTMEMc
CbDcbA9N3HqH7ecNsMYlqSkbsmM7XteXTNwILjDiB9lfAgMBAAGjgZYwgZMwHQYD
VR0OBBYEFO4m1RvgY2O+c37Q6aNTJagGD7LWMB8GA1UdIwQYMBaAFO4m1RvgY2O+
c37Q6aNTJagGD7LWMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxo
b3N0MAsGA1UdDwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DQYJKoZIhvcNAQELBQADggEBAESeQG65OStjQ/DZH4AymiVb0IKc7lFg6uRSE8rV
zqPD8WmHJ9KKPVxsH2/cpG8GUc/F/yreL60JFD2qobif4edPYjzOti+Sa9b+aVfD
+NSszIQ+PYg3lEdK+WhpZfAst7oeczSrlahFxviXmwA+1coBjdkSZm+bAyR4ILhW
NtfeBQthrycnDLqRjKgH18N2zPHLTF9fPeB2Qv197HCee8NUC5/+TWBYhEyE5ty2
EPXBVJBgp/NtkRG2Exmz/DaBmOWXADNMf3S/7ktFkVTd+a9UR8wO9Rdohhz/c/vz
40LdlG7ED4Z3rKyPfrhZz24L+vp3+lgiXGZ/4yu/8zgJwNg=
-----END CERTIFICATE-----
`

var clientRSA2048Key = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCfF/E6bOzzqkEr
SR3Sh54EnOcZBHU6yRkU8A00NakSCCoTQYrjLCteTPVow7ghBgjzxnl+5GNAgARF
m/yv3ashueLlc+B5VJ15jgbvB4hxhYVlngptlpwTMF1mZfmZgC/YFEW8GFT5umRD
f6itYlRHC43JMq/bJ1ZPse80su/5IvXKd4lSBv/ef05oWNqmAaeqtE7eLhdMZxk2
ZcFZrHwVyZDAI99TuFpquMQ4mrNNZFt391a4YroURl7fWOYf2HHM1IHOXb6Feduk
OMUf/TLOIHxV18fEyE6YERfTMEMcCbDcbA9N3HqH7ecNsMYlqSkbsmM7XteXTNwI
LjDiB9lfAgMBAAECggEAGJM+uJs12QfeLD0NpcU8NBM2oYcuQqfov3K7X2rAlJ/9
O98+gIwEoPr7V7UP/s3rWRi6EM9fw4li34vScyonMrz/nxkQvj1DXBED4i2ENqD8
867/hmEi99XbP6OV9E+4VEUBZqZNjgvsS/7uw+WyBg1zV/aD8rL3YrUmMbpIVnAA
+jW0EqFu600BtDU2iBTfpIHkyhRBGq+wWdebPdj/qSuKxv53S2g8MqTnREFp7RX2
CrdAtjJoe50yJnzjHjgRPoW8prCT4q3yC8dCHIT8Spgt5SnhFw4F/sgZRJDXk7Yt
8wLqPGF5TvJMvzxS+sopDwi+Wv/Yee5jal7o5vs05QKBgQDb+fH+b0slzWVaeCPv
Y924iDzIwlosnnwVX4P0M9jMuvcN03gx9n0NoIYV9xnvCYW5oj+/cIUhHKXu9z6z
1MHX4WFcmUgZq2HFdmgCttF0xtXaEWJmNhp9RpfuqHjDa7pfu+E1HtxiIKix9QhU
R8BO7UGf+aYQHzgul7bjPZqsewKBgQC5JZw0ryJUNo3o1OKtZa9Df1XFGd3tDtNh
+NgwnjpqgTdvmpFlX5HrmYEC9zQDj2tklWP0Jqwn0SJiSNoj2fJJ/uWBKv0tG7HU
g4h29TyqIALRKtxFMug0pzvwI5H7GpziAhY4G3XXu2zQ0Sr5dOLgJPZsc1gEM/9A
A02ve69rbQKBgEvMBhx70NMHwSK5Pvif2qhZGUi730J8oZjjvp4It21kBvjWoxXk
Lxbg9xLegCsjhtZ+F6UpalYMfwimXQ6uAtUWLewwTO27ZgcaU6CLygSI9usbDmLV
xa7hAj0UA/iiSCfwnxsktR+CzV30ZphT2OnZSsGKzjPD7iHv2O7YLVG9AoGAMst6
u4mA5ZHCBSrCtce7+cypf1XFaRA0NiDLTytZ43Zn+xpw4VsC8Zw/pMylXISwdfv2
XDlv6cyanlRWZJeavWpNFM7yfrmmZCNiASDu782weCpGHEYHJsrqyss3daireeYQ
qnv+LJ2jEPcRzzaeN9hsMvzCHQUW9jzxxz8rtVECgYAfolbY3MKceRflivbEgzoN
NE2/2drUN2HtNQXgmssAXFIz/NH7Yz8FDxV9I7Rdty4Z3o11i/U7sQNp/j//lZwz
Rx7Se7Axid6XTqws8Xc++oRBoXDbUi04hP0mlu/j0++usph9xIzmwAUc8I0PiYlc
OFkq5rANUk+ih+3rxwEB0A==
-----END PRIVATE KEY-----
`

var serverECCCert = `
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

var serverECCKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII5YGc+PoVV8Xn1nJlWjJc00KEGPeZKu5npjhh2VBZnIoAoGCCqGSM49
AwEHoUQDQgAEStmZQMcRkN1leCNSWrfakl3kmvgmv/xREdaHJg8LR4isAEE5ElN5
xwLQ+bDoLhQl4rcNyqm7X/76x8GEP8n6xQ==
-----END EC PRIVATE KEY-----
`

var clientECCCert = `
-----BEGIN CERTIFICATE-----
MIIB4TCCAYagAwIBAgIUKmZO960blkGzxh8WvbR89zKtdvIwCgYIKoZIzj0EAwIw
ITELMAkGA1UEBhMCQ04xEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0yNjEwMTgwNDI4
MDdaGA8yMTI2MDkyNDA0MjgwN1owITELMAkGA1UEBhMCQ04xEjAQBgNVBAMMCWxv
Y2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJvUYO8SZKMBt6WJPGWd
qc9zdOnWjBGV7ERzzYTZ2e09l1OLuPaiXe+I1jWJofJfdjPrMv3WYWBGilUj1cYi
uEWjgZkwgZYwHQYDVR0OBBYEFBiz0qMt5Fb2PO8ZXHoUeGcvT0ZaMB8GA1UdIwQY
MBaAFBiz0qMt5Fb2PO8ZXHoUeGcvT0ZaMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0R
BA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSQAwRgIhAK0AcEiEHj1mQbdpnLws
Uoon8iyGfXghIqJTD8pHX+HiAiEAtTslvMz5m2LBLZfeSCJv3/zZfnDFr+y4frK2
YKmElIg=
-----END CERTIFICATE-----
`

var clientECCKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICNodowA7GYdU5eNzPfrFMKN47e4or/lBsYf8oMO96JMoAoGCCqGSM49
AwEHoUQDQgAEm9Rg7xJkowG3pYk8ZZ2pz3N06daMEZXsRHPNhNnZ7T2XU4u49qJd
74jWNYmh8l92M+sy/dZhYEaKVSPVxiK4RQ==
-----END EC PRIVATE KEY-----
`

func init() {
	os.WriteFile("server-rsa2048.crt", []byte(serverRSA2048Cert), 0o777)
	os.WriteFile("server-rsa2048.key", []byte(serverRSA2048Key), 0o777)
	os.WriteFile("client-rsa2048.crt", []byte(clientRSA2048Cert), 0o777)
	os.WriteFile("client-rsa2048.key", []byte(clientRSA2048Key), 0o777)

	os.WriteFile("server-ecc.crt", []byte(serverECCCert), 0o777)
	os.WriteFile("server-ecc.key", []byte(serverECCKey), 0o777)
	os.WriteFile("client-ecc.crt", []byte(clientECCCert), 0o777)
	os.WriteFile("client-ecc.key", []byte(clientECCKey), 0o777)
}
