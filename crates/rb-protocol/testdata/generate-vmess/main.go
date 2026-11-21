// Generates crates/rb-protocol/testdata/vmess_vectors.json with sing-vmess
// (the version sing-box v1.14.4 uses): the wire bytes of a sing-vmess
// client's requests and of the sing-vmess server's responses, for each
// security, option and header kind.
//
//	cd crates/rb-protocol/testdata/generate-vmess && go run . > ../vmess_vectors.json
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const userID = "bf000d23-0752-40b4-affe-68f7707a9661"

type recorder struct {
	net.Conn
	access  sync.Mutex
	written []byte
	read    []byte
}

func (r *recorder) Write(p []byte) (int, error) {
	r.access.Lock()
	r.written = append(r.written, p...)
	r.access.Unlock()
	return r.Conn.Write(p)
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.access.Lock()
	r.read = append(r.read, p[:n]...)
	r.access.Unlock()
	return n, err
}

func pattern(size int, seed byte) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = seed + byte(i*7)
	}
	return data
}

type handler struct {
	request  []byte
	response []byte
	packets  int
	done     chan struct{}
}

func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer close(h.done)
	data := make([]byte, len(h.request))
	if _, err := io.ReadFull(conn, data); err != nil {
		panic(err)
	}
	if string(data) != string(h.request) {
		panic("request payload mismatch")
	}
	if _, err := conn.Write(append([]byte(nil), h.response...)); err != nil {
		panic(err)
	}
	conn.Close()
}

func (h *handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer close(h.done)
	for i := 0; i < h.packets; i++ {
		buffer := buf.New()
		_, err := conn.ReadPacket(buffer)
		if err != nil {
			panic(err)
		}
		if string(buffer.Bytes()) != string(h.request) {
			panic("packet mismatch")
		}
		buffer.Release()
		reply := buf.NewSize(1024)
		reply.Resize(64, 0)
		common.Must1(reply.Write(h.response))
		if err := conn.WritePacket(reply, destination); err != nil {
			panic(err)
		}
	}
	conn.Close()
}

type vector struct {
	Name                string `json:"name"`
	Security            string `json:"security"`
	AlterID             int    `json:"alter_id"`
	GlobalPadding       bool   `json:"global_padding"`
	AuthenticatedLength bool   `json:"authenticated_length"`
	Command             string `json:"command"`
	Destination         string `json:"destination"`
	Time                int64  `json:"time"`
	RequestPayload      string `json:"request_payload"`
	ResponsePayload     string `json:"response_payload"`
	Packets             int    `json:"packets"`
	Request             string `json:"request"`
	Response            string `json:"response"`
}

func generate(name, security string, alterID int, padding, authLength bool, command string, requestSize, responseSize int) vector {
	now := time.Now().Truncate(time.Second)
	timeFunc := func() time.Time { return now }
	var options []vmess.ClientOption
	options = append(options, vmess.ClientWithTimeFunc(timeFunc))
	if padding {
		options = append(options, vmess.ClientWithGlobalPadding())
	}
	if authLength {
		options = append(options, vmess.ClientWithAuthenticatedLength())
	}
	client, err := vmess.NewClient(userID, security, alterID, options...)
	if err != nil {
		panic(err)
	}
	h := &handler{request: pattern(requestSize, 1), response: pattern(responseSize, 100), done: make(chan struct{})}
	service := vmess.NewService[int](h, vmess.ServiceWithTimeFunc(timeFunc))
	if err := service.UpdateUsers([]int{0}, []string{userID}, []int{alterID}); err != nil {
		panic(err)
	}
	clientSide, serverSide := net.Pipe()
	rec := &recorder{Conn: clientSide}
	destination := M.ParseSocksaddr("example.com:443")
	go func() {
		if err := service.NewConnection(context.Background(), serverSide, M.ParseSocksaddr("127.0.0.1:1"), nil); err != nil {
			panic(err)
		}
	}()
	switch command {
	case "tcp":
		conn := client.DialEarlyConn(rec, destination)
		if _, err := conn.Write(append([]byte(nil), h.request...)); err != nil {
			panic(err)
		}
		response, err := io.ReadAll(conn)
		if err != nil {
			panic(err)
		}
		if string(response) != string(h.response) {
			panic("response mismatch")
		}
	case "udp":
		destination = M.ParseSocksaddr("1.2.3.4:53")
		h.packets = 2
		conn := client.DialEarlyPacketConn(rec, destination)
		for i := 0; i < h.packets; i++ {
			if _, err := conn.WriteTo(append([]byte(nil), h.request...), destination.UDPAddr()); err != nil {
				panic(err)
			}
			buffer := make([]byte, 65535)
			n, _, err := conn.ReadFrom(buffer)
			if err != nil {
				panic(err)
			}
			if string(buffer[:n]) != string(h.response) {
				panic("reply mismatch")
			}
		}
		io.Copy(io.Discard, rec)
	}
	<-h.done
	return vector{
		Name: name, Security: security, AlterID: alterID, GlobalPadding: padding, AuthenticatedLength: authLength,
		Command: command, Destination: destination.String(), Time: now.Unix(),
		RequestPayload: hex.EncodeToString(h.request), ResponsePayload: hex.EncodeToString(h.response), Packets: h.packets,
		Request: hex.EncodeToString(rec.written), Response: hex.EncodeToString(rec.read),
	}
}

func main() {
	var vectors []vector
	for _, security := range []string{"none", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb"} {
		for _, alterID := range []int{0, 2} {
			for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
				name := security
				if alterID > 0 {
					name += "_legacy"
				}
				if flags[0] {
					name += "_padding"
				}
				if flags[1] {
					name += "_authlen"
				}
				vectors = append(vectors, generate(name+"_tcp", security, alterID, flags[0], flags[1], "tcp", 100, 70))
				vectors = append(vectors, generate(name+"_udp", security, alterID, flags[0], flags[1], "udp", 30, 40))
			}
		}
		vectors = append(vectors, generate(security+"_tcp_large", security, 0, true, false, "tcp", 15500, 15100))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(vectors); err != nil {
		panic(err)
	}
}
