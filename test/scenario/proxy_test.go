package scenario

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"testing"
	"time"

	netproxy "golang.org/x/net/proxy"

	_ "github.com/p4gefau1t/trojan-go/api"
	_ "github.com/p4gefau1t/trojan-go/api/service"
	"github.com/p4gefau1t/trojan-go/common"
	_ "github.com/p4gefau1t/trojan-go/log/golog"
	"github.com/p4gefau1t/trojan-go/proxy"
	_ "github.com/p4gefau1t/trojan-go/proxy/client"
	_ "github.com/p4gefau1t/trojan-go/proxy/forward"
	_ "github.com/p4gefau1t/trojan-go/proxy/nat"
	_ "github.com/p4gefau1t/trojan-go/proxy/server"
	_ "github.com/p4gefau1t/trojan-go/statistic/memory"
	"github.com/p4gefau1t/trojan-go/test/util"
)

// test key and cert

var cert = `
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

var key = `
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

func init() {
	os.WriteFile("server.crt", []byte(cert), 0o777)
	os.WriteFile("server.key", []byte(key), 0o777)
}

func CheckClientServer(clientData, serverData string, socksPort int) (ok bool) {
	server, err := proxy.NewProxyFromConfigData([]byte(serverData), false)
	common.Must(err)
	go server.Run()

	client, err := proxy.NewProxyFromConfigData([]byte(clientData), false)
	common.Must(err)
	go client.Run()

	time.Sleep(time.Second * 2)
	dialer, err := netproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, netproxy.Direct)
	common.Must(err)

	ok = true
	const num = 100
	wg := sync.WaitGroup{}
	wg.Add(num)
	for i := 0; i < num; i++ {
		go func() {
			const payloadSize = 1024
			payload := util.GeneratePayload(payloadSize)
			buf := [payloadSize]byte{}

			conn, err := dialer.Dial("tcp", util.EchoAddr)
			common.Must(err)

			common.Must2(conn.Write(payload))
			common.Must2(conn.Read(buf[:]))

			if !bytes.Equal(payload, buf[:]) {
				ok = false
			}
			conn.Close()
			wg.Done()
		}()
	}
	wg.Wait()
	client.Close()
	server.Close()
	return
}

func TestClientServerWebsocketSubTree(t *testing.T) {
	serverPort := common.PickPort("tcp", "127.0.0.1")
	socksPort := common.PickPort("tcp", "127.0.0.1")
	clientData := fmt.Sprintf(`
run-type: client
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %d
password:
    - password
ssl:
    verify: false
    fingerprint: firefox
    sni: localhost
websocket:
    enabled: true
    path: /ws
    host: somedomainname.com
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
mux:
    enabled: true
`, socksPort, serverPort)
	serverData := fmt.Sprintf(`
run-type: server
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %s
disable-http-check: true
password:
    - password
ssl:
    verify-hostname: false
    key: server.key
    cert: server.crt
    sni: localhost
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
websocket:
    enabled: true
    path: /ws
    host: 127.0.0.1
`, serverPort, util.HTTPPort)

	if !CheckClientServer(clientData, serverData, socksPort) {
		t.Fail()
	}
}

func TestClientServerTrojanSubTree(t *testing.T) {
	serverPort := common.PickPort("tcp", "127.0.0.1")
	socksPort := common.PickPort("tcp", "127.0.0.1")
	clientData := fmt.Sprintf(`
run-type: client
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %d
password:
    - password
ssl:
    verify: false
    fingerprint: firefox
    sni: localhost
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
mux:
    enabled: true
`, socksPort, serverPort)
	serverData := fmt.Sprintf(`
run-type: server
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %s
disable-http-check: true
password:
    - password
ssl:
    verify-hostname: false
    key: server.key
    cert: server.crt
    sni: localhost
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
`, serverPort, util.HTTPPort)

	if !CheckClientServer(clientData, serverData, socksPort) {
		t.Fail()
	}
}

func TestWebsocketDetection(t *testing.T) {
	serverPort := common.PickPort("tcp", "127.0.0.1")
	socksPort := common.PickPort("tcp", "127.0.0.1")

	clientData := fmt.Sprintf(`
run-type: client
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %d
password:
    - password
ssl:
    verify: false
    fingerprint: firefox
    sni: localhost
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
mux:
    enabled: true
`, socksPort, serverPort)
	serverData := fmt.Sprintf(`
run-type: server
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %s
disable-http-check: true
password:
    - password
ssl:
    verify-hostname: false
    key: server.key
    cert: server.crt
    sni: localhost
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
websocket:
    enabled: true
    path: /ws
    hostname: 127.0.0.1
`, serverPort, util.HTTPPort)

	if !CheckClientServer(clientData, serverData, socksPort) {
		t.Fail()
	}
}

func TestPluginWebsocket(t *testing.T) {
	serverPort := common.PickPort("tcp", "127.0.0.1")
	socksPort := common.PickPort("tcp", "127.0.0.1")

	clientData := fmt.Sprintf(`
run-type: client
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %d
password:
    - password
transport-plugin:
    enabled: true
    type: plaintext
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
mux:
    enabled: true
websocket:
    enabled: true
    path: /ws
    hostname: 127.0.0.1
`, socksPort, serverPort)
	serverData := fmt.Sprintf(`
run-type: server
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %s
disable-http-check: true
password:
    - password
transport-plugin:
    enabled: true
    type: plaintext
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
websocket:
    enabled: true
    path: /ws
    hostname: 127.0.0.1
`, serverPort, util.HTTPPort)

	if !CheckClientServer(clientData, serverData, socksPort) {
		t.Fail()
	}
}

func TestForward(t *testing.T) {
	serverPort := common.PickPort("tcp", "127.0.0.1")
	clientPort := common.PickPort("tcp", "127.0.0.1")
	_, targetPort, _ := net.SplitHostPort(util.EchoAddr)
	clientData := fmt.Sprintf(`
run-type: forward
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %d
target-addr: 127.0.0.1
target-port: %s
password:
    - password
ssl:
    verify: false
    fingerprint: firefox
    sni: localhost
websocket:
    enabled: true
    path: /ws
    hostname: 127.0.0.1
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
mux:
    enabled: true
`, clientPort, serverPort, targetPort)
	go func() {
		proxy, err := proxy.NewProxyFromConfigData([]byte(clientData), false)
		common.Must(err)
		common.Must(proxy.Run())
	}()

	serverData := fmt.Sprintf(`
run-type: server
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %s
disable-http-check: true
password:
    - password
ssl:
    verify-hostname: false
    key: server.key
    cert: server.crt
    sni: "localhost"
websocket:
    enabled: true
    path: /ws
    hostname: 127.0.0.1
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
`, serverPort, util.HTTPPort)
	go func() {
		proxy, err := proxy.NewProxyFromConfigData([]byte(serverData), false)
		common.Must(err)
		common.Must(proxy.Run())
	}()

	time.Sleep(time.Second * 2)

	payload := util.GeneratePayload(1024)
	buf := [1024]byte{}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort))
	common.Must(err)

	common.Must2(conn.Write(payload))
	common.Must2(conn.Read(buf[:]))

	if !bytes.Equal(payload, buf[:]) {
		t.Fail()
	}

	packet, err := net.ListenPacket("udp", "")
	common.Must(err)
	common.Must2(packet.WriteTo(payload, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: clientPort,
	}))
	_, _, err = packet.ReadFrom(buf[:])
	common.Must(err)
	if !bytes.Equal(payload, buf[:]) {
		t.Fail()
	}
}

func TestLeak(t *testing.T) {
	serverPort := common.PickPort("tcp", "127.0.0.1")
	socksPort := common.PickPort("tcp", "127.0.0.1")
	clientData := fmt.Sprintf(`
run-type: client
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %d
log-level: 0
password:
    - password
ssl:
    verify: false
    fingerprint: firefox
    sni: localhost
shadowsocks:
    enabled: true
    method: AEAD_CHACHA20_POLY1305
    password: 12345678
mux:
    enabled: true
api:
    enabled: true
    api-port: 0
`, socksPort, serverPort)
	client, err := proxy.NewProxyFromConfigData([]byte(clientData), false)
	common.Must(err)
	go client.Run()
	time.Sleep(time.Second * 3)
	client.Close()
	time.Sleep(time.Second * 3)
	// http.ListenAndServe("localhost:6060", nil)
}

func SingleThreadBenchmark(clientData, serverData string, socksPort int) {
	server, err := proxy.NewProxyFromConfigData([]byte(clientData), false)
	common.Must(err)
	go server.Run()

	client, err := proxy.NewProxyFromConfigData([]byte(serverData), false)
	common.Must(err)
	go client.Run()

	time.Sleep(time.Second * 2)
	dialer, err := netproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, netproxy.Direct)
	common.Must(err)

	const num = 100
	wg := sync.WaitGroup{}
	wg.Add(num)
	const payloadSize = 1024 * 1024 * 1024
	payload := util.GeneratePayload(payloadSize)

	for i := 0; i < 100; i++ {
		conn, err := dialer.Dial("tcp", util.BlackHoleAddr)
		common.Must(err)

		t1 := time.Now()
		common.Must2(conn.Write(payload))
		t2 := time.Now()

		speed := float64(payloadSize) / (float64(t2.Sub(t1).Nanoseconds()) / float64(time.Second))
		fmt.Printf("speed: %f Gbps\n", speed/1024/1024/1024)

		conn.Close()
	}
	client.Close()
	server.Close()
}

func BenchmarkClientServer(b *testing.B) {
	go func() {
		fmt.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	serverPort := common.PickPort("tcp", "127.0.0.1")
	socksPort := common.PickPort("tcp", "127.0.0.1")
	clientData := fmt.Sprintf(`
run-type: client
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %d
log-level: 0
password:
    - password
ssl:
    verify: false
    fingerprint: firefox
    sni: localhost
`, socksPort, serverPort)
	serverData := fmt.Sprintf(`
run-type: server
local-addr: 127.0.0.1
local-port: %d
remote-addr: 127.0.0.1
remote-port: %s
log-level: 0
disable-http-check: true
password:
    - password
ssl:
    verify-hostname: false
    key: server.key
    cert: server.crt
    sni: localhost
`, serverPort, util.HTTPPort)

	SingleThreadBenchmark(clientData, serverData, socksPort)
}
