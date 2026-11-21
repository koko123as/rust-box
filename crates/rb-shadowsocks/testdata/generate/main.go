// Generates ../vectors.json: shadowsocks bytes produced by the Go
// libraries sing-box v1.14.4 uses (sing-shadowsocks2 clients,
// sing-shadowsocks services), which rust-box's unit tests decode.
//
//	cd crates/rb-shadowsocks/testdata/generate && go run .
package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"time"

	ss1 "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	ss2 "github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

// captureConn reads from `in` and records what is written.
type captureConn struct {
	in  io.Reader
	out bytes.Buffer
}

func (c *captureConn) Read(p []byte) (int, error)         { return c.in.Read(p) }
func (c *captureConn) Write(p []byte) (int, error)        { return c.out.Write(p) }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return M.ParseSocksaddr("127.0.0.1:1") }
func (c *captureConn) RemoteAddr() net.Addr               { return M.ParseSocksaddr("127.0.0.1:2") }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

func h(b []byte) string { return hex.EncodeToString(b) }

type KeyVector struct {
	Password string `json:"password"`
	Size     int    `json:"size"`
	Key      string `json:"key"`
}

type DeriveVector struct {
	Key  string `json:"key"`
	Salt string `json:"salt"`
	Size int    `json:"size"`
	Out  string `json:"out"`
}

type TcpVector struct {
	Method         string `json:"method"`
	ClientPassword string `json:"client_password"`
	ServerPassword string `json:"server_password"`
	Users          []string `json:"users"`
	Destination    string `json:"destination"`
	Payload        string `json:"payload"`
	Request        string `json:"request"`
	ServerPayload  string `json:"server_payload"`
	Response       string `json:"response"`
}

type UdpVector struct {
	Method      string `json:"method"`
	Password    string `json:"password"`
	Destination string `json:"destination"`
	Payload     string `json:"payload"`
	Packet      string `json:"packet"`
}

type Vectors struct {
	Time            int64              `json:"time"`
	Keys            []KeyVector        `json:"keys"`
	AeadSubkeys     []DeriveVector     `json:"aead_subkeys"`
	SessionKeys     []DeriveVector     `json:"session_keys"`
	IdentitySubkeys []DeriveVector     `json:"identity_subkeys"`
	PskHashes       map[string]string  `json:"psk_hashes"`
	Sha256Keys      []DeriveVector     `json:"sha256_keys"`
	Base64Errors    map[string]string  `json:"base64_errors"`
	Tcp             []TcpVector        `json:"tcp"`
	Udp             []UdpVector        `json:"udp"`
}

type handler struct {
	payload  []byte
	response []byte
}

func (s *handler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	s.payload = make([]byte, 5)
	if _, err := io.ReadFull(conn, s.payload); err != nil {
		return err
	}
	_, err := conn.Write(s.response)
	return err
}

func (s *handler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (s *handler) NewError(ctx context.Context, err error) { panic(err) }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

const (
	psk16  = "AAECAwQFBgcICQoLDA0ODw=="
	upsk16 = "EBESExQVFhcYGRobHB0eHw=="
	psk32  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

func main() {
	v := Vectors{Time: time.Now().Unix(), PskHashes: map[string]string{}, Base64Errors: map[string]string{}}
	now := func() time.Time { return time.Unix(v.Time, 0) }

	for _, size := range []int{16, 24, 32} {
		v.Keys = append(v.Keys, KeyVector{"test-password", size, h(ss1.Key([]byte("test-password"), size))})
	}
	salt := []byte("0123456789abcdef0123456789abcdef")
	for _, size := range []int{16, 24, 32} {
		key := ss1.Key([]byte("k"), size)
		out := make([]byte, size)
		io.ReadFull(hkdf.New(sha1.New, key, salt[:size], []byte("ss-subkey")), out)
		v.AeadSubkeys = append(v.AeadSubkeys, DeriveVector{h(key), h(salt[:size]), size, h(out)})
	}
	for _, size := range []int{16, 32} {
		key, _ := base64.StdEncoding.DecodeString(map[int]string{16: psk16, 32: psk32}[size])
		v.SessionKeys = append(v.SessionKeys, DeriveVector{h(key), h(salt[:size]), size, h(shadowaead_2022.SessionKey(key, salt[:size], size))})
		material := append(append([]byte{}, key...), salt[:size]...)
		out := make([]byte, size)
		blake3.DeriveKey(out, "shadowsocks 2022 identity subkey", material)
		v.IdentitySubkeys = append(v.IdentitySubkeys, DeriveVector{h(key), h(salt[:size]), size, h(out)})
		hash := blake3.Sum512(key)
		v.PskHashes[h(key)] = h(hash[:16])
		long := []byte("a key longer than thirty-two bytes, hashed down")
		sum := sha256.Sum256(long)
		v.Sha256Keys = append(v.Sha256Keys, DeriveVector{Key: h(long), Size: size, Out: h(sum[:size])})
	}
	for _, input := range []string{"abc", "ab=c", "!!!!", "AAAA=", "AAAAAAAAAAAAAAAAAAAAAA", "AAAA AAAA", "AAAAAA==AA", "AAA="} {
		_, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			v.Base64Errors[input] = err.Error()
		} else {
			v.Base64Errors[input] = ""
		}
	}

	tcpCase := func(method, clientPassword, serverPassword string, users []string, destination string) {
		m, err := ss2.CreateMethod(context.Background(), method, ss2.MethodOptions{Password: clientPassword})
		must(err)
		client := &captureConn{in: bytes.NewReader(nil)}
		conn, err := m.DialConn(client, M.ParseSocksaddr(destination))
		must(err)
		_, err = conn.Write([]byte("hello"))
		must(err)
		vector := TcpVector{Method: method, ClientPassword: clientPassword, ServerPassword: serverPassword, Users: users,
			Destination: destination, Payload: h([]byte("hello")), Request: h(client.out.Bytes()), ServerPayload: h([]byte("world"))}
		// A server's response to that request.
		hd := &handler{response: []byte("world")}
		var service interface {
			NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error
		}
		switch {
		case method == "none" || len(method) > 4 && method[len(method)-4:] == "-ctr" || len(method) > 4 && method[len(method)-4:] == "-cfb" || method == "rc4-md5" || method == "chacha20-ietf" || method == "xchacha20":
			// No Go server (or a symmetric one): the response is built
			// like a request by the client code below.
			service = nil
		case len(users) > 0 && method[:4] == "2022":
			s, err := shadowaead_2022.NewMultiServiceWithPassword[int](method, serverPassword, 300, hd, now)
			must(err)
			ids := make([]int, len(users))
			for i := range ids {
				ids[i] = i
			}
			must(s.UpdateUsersWithPasswords(ids, users))
			service = s
		case len(users) > 0:
			s, err := shadowaead.NewMultiService[int](method, 300, hd)
			must(err)
			ids := make([]int, len(users))
			for i := range ids {
				ids[i] = i
			}
			must(s.UpdateUsersWithPasswords(ids, users))
			service = s
		case method[:4] == "2022":
			s, err := shadowaead_2022.NewServiceWithPassword(method, serverPassword, 300, hd, now)
			must(err)
			service = s
		default:
			s, err := shadowaead.NewService(method, nil, serverPassword, 300, hd)
			must(err)
			service = s
		}
		if service != nil {
			server := &captureConn{in: bytes.NewReader(client.out.Bytes())}
			must(service.NewConnection(context.Background(), server, M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:3")}))
			if string(hd.payload) != "hello" {
				panic("payload")
			}
			vector.Response = h(server.out.Bytes())
		}
		v.Tcp = append(v.Tcp, vector)
	}
	for _, method := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
		tcpCase(method, "test-password", "test-password", nil, "example.com:443")
	}
	tcpCase("aes-128-gcm", "user-b", "", []string{"user-a", "user-b"}, "1.2.3.4:80")
	tcpCase("2022-blake3-aes-128-gcm", psk16, psk16, nil, "example.com:443")
	tcpCase("2022-blake3-aes-256-gcm", psk32, psk32, nil, "[2001:db8::1]:443")
	tcpCase("2022-blake3-chacha20-poly1305", psk32, psk32, nil, "example.com:443")
	tcpCase("2022-blake3-aes-128-gcm", psk16+":"+upsk16, psk16, []string{"AQEBAQEBAQEBAQEBAQEBAQ==", upsk16}, "example.com:443")
	for _, method := range []string{"none", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20"} {
		tcpCase(method, "test-password", "", nil, "example.com:443")
	}

	udpCase := func(method, password, destination string) {
		m, err := ss2.CreateMethod(context.Background(), method, ss2.MethodOptions{Password: password})
		must(err)
		client := &captureConn{in: bytes.NewReader(nil)}
		conn := m.DialPacketConn(client)
		payload := []byte("ping")
		_, err = conn.WriteTo(payload, M.ParseSocksaddr(destination))
		must(err)
		v.Udp = append(v.Udp, UdpVector{method, password, destination, h(payload), h(client.out.Bytes())})
	}
	for _, method := range []string{"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
		"aes-128-ctr", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20"} {
		udpCase(method, "test-password", "example.com:53")
	}
	udpCase("2022-blake3-aes-128-gcm", psk16, "1.2.3.4:53")
	udpCase("2022-blake3-aes-128-gcm", psk16, "example.com:443")
	udpCase("2022-blake3-aes-256-gcm", psk32, "[2001:db8::1]:53")
	udpCase("2022-blake3-chacha20-poly1305", psk32, "1.2.3.4:53")
	udpCase("2022-blake3-aes-128-gcm", psk16+":"+upsk16, "1.2.3.4:53")
	_ = buf.New

	data, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile("../vectors.json", append(data, '\n'), 0o644))
}
