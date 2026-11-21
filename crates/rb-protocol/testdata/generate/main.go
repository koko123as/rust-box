// Generates ../vless_vectors.json: VLESS bytes produced by the Go
// libraries sing-box v1.14.4 uses (sing-vmess, gofrs/uuid), which
// rust-box's unit tests compare against.
//
//	cd crates/rb-protocol/testdata/generate && go run .
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"time"

	"github.com/gofrs/uuid/v5"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// captureConn records what is written.
type captureConn struct {
	out bytes.Buffer
}

func (c *captureConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(p []byte) (int, error)        { return c.out.Write(p) }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

// userID is sing-vmess's mapping of a `uuid` option.
func userID(text string) [16]byte {
	user, err := uuid.FromString(text)
	if err != nil {
		user = uuid.NewV5(uuid.Nil, text)
	}
	return user
}

// headroom is a buffer with room in front, as sing's writers expect.
func headroom(data string) *buf.Buffer {
	buffer := buf.NewSize(128 + len(data))
	buffer.Resize(128, 0)
	buffer.WriteString(data)
	return buffer
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	vectors := map[string]any{}

	uuids := map[string]string{}
	for _, text := range []string{
		"bf000d23-0752-40b4-affe-68f7707a9661",
		"{BF000D23-0752-40B4-AFFE-68F7707A9661}",
		"urn:uuid:bf000d23075240b4affe68f7707a9661",
		"bf000d23075240b4affe68f7707a9661",
		"password",
		"",
		"bf000d23-0752-40b4-affe-68f7707a966",
		"测试用户",
	} {
		id := userID(text)
		uuids[text] = hex.EncodeToString(id[:])
	}
	vectors["uuid"] = uuids

	user := userID("bf000d23-0752-40b4-affe-68f7707a9661")
	requests := map[string]string{}
	var buffer bytes.Buffer
	must(vless.WriteRequest(&buffer, vless.Request{UUID: user, Command: vmess.CommandTCP,
		Destination: M.ParseSocksaddrHostPort("example.com", 443), Flow: vless.FlowVision}, nil))
	requests["tcp_vision_domain"] = hex.EncodeToString(buffer.Bytes())
	buffer.Reset()
	must(vless.WriteRequest(&buffer, vless.Request{UUID: user, Command: vmess.CommandTCP,
		Destination: M.ParseSocksaddrHostPort("2001:db8::1", 80)}, []byte("payload")))
	requests["tcp_ipv6_payload"] = hex.EncodeToString(buffer.Bytes())
	buffer.Reset()
	must(vless.WriteRequest(&buffer, vless.Request{UUID: user, Command: vmess.CommandMux, Flow: vless.FlowVision}, nil))
	requests["mux_vision"] = hex.EncodeToString(buffer.Bytes())
	buffer.Reset()
	must(vless.WritePacketRequest(&buffer, vless.Request{UUID: user, Command: vmess.CommandUDP,
		Destination: M.ParseSocksaddrHostPort("1.2.3.4", 53), Flow: vless.FlowVision}, nil))
	requests["udp_ipv4"] = hex.EncodeToString(buffer.Bytes())
	buffer.Reset()
	must(vless.WritePacketRequest(&buffer, vless.Request{UUID: user, Command: vmess.CommandUDP,
		Destination: M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress}}, nil))
	requests["udp_packetaddr"] = hex.EncodeToString(buffer.Bytes())
	vectors["request"] = requests

	// XUDP frames of a client (two packets).
	capture := &captureConn{}
	xudp := vmess.NewXUDPConn(capture, M.ParseSocksaddrHostPort("8.8.8.8", 53))
	must(xudp.WritePacket(headroom("first"), M.ParseSocksaddrHostPort("8.8.8.8", 53)))
	must(xudp.WritePacket(headroom("second"), M.ParseSocksaddrHostPort("example.com", 5353)))
	vectors["xudp_client"] = hex.EncodeToString(capture.out.Bytes())

	// packetaddr payload framing.
	capture = &captureConn{}
	vlessConn, err := vless.NewClient("bf000d23-0752-40b4-affe-68f7707a9661", "", nil)
	must(err)
	packetConn, err := vlessConn.DialEarlyPacketConn(capture, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
	must(err)
	addressed := packetaddr.NewConn(packetConn, M.ParseSocksaddrHostPort("1.1.1.1", 53))
	_, err = addressed.WriteTo([]byte("query"), M.ParseSocksaddrHostPort("1.1.1.1", 53).UDPAddr())
	must(err)
	vectors["packetaddr_client"] = hex.EncodeToString(capture.out.Bytes())

	output, err := json.MarshalIndent(vectors, "", "  ")
	must(err)
	must(os.WriteFile("../vless_vectors.json", append(output, '\n'), 0o644))
}
