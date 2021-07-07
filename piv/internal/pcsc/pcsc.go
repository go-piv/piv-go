// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pcsc implements the libpcsclite protocol for communicating with pcscd.
//
// This package is a pure Go implementation of libpcsclite, allowing piv-go to
// communicate directly with pcscd without cgo. This still relies on pcscd to
// communicate with the OS, and will be less reliable than linking against the
// shared libraries provided by the pcscd packages.
//
// This package will NOT work with the native Mac and Windows libraries, which
// are provided directly by the OS. Though pcsclite can be installed on Mac.
package pcsc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
)

// pcscd messages directly encode C structs over a unix domain socket. Determine
// the host's byte order with build tags so encoding/binary can replicate this
// behavior.
//
// https://groups.google.com/g/golang-nuts/c/3GEzwKfRRQw/m/ppkJKrT4cfAJ
var nativeByteOrder binary.ByteOrder

const (
	pcscSocketPathEnv = "PCSCLITE_CSOCK_NAME"
	pcscSocketPath    = "/run/pcscd/pcscd.comm"
)

const (
	// RVSuccess is a return value indicating the operation succeeded.
	RVSuccess = 0

	majorVersion = 4
	minorVersion = 4

	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L76
	commandEstablishContext = 0x01
	commandReleaseContext   = 0x02
	commandConnect          = 0x04
	commandDisconnect       = 0x05
	commandBeginTransaction = 0x07
	commandEndTransaction   = 0x08
	commandTransmit         = 0x09
	commandVersion          = 0x11
	commandGetReadersState  = 0x12

	// Context modes to be passed to NewContext.
	//
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L248
	Exclusive = 0x0001
	Shared    = 0x0002
	Direct    = 0x0003

	// Different protocols that can be used when connecting to a card.
	ProtocolT0  = 0x0001
	ProtocolT1  = 0x0002
	ProtocolRaw = 0x0004
	ProtocolT15 = 0x0005

	// Disconnect option.
	LeaveCard   = 0x0000
	ResetCard   = 0x0001
	UnpowerCard = 0x0002
	EjectCard   = 0x0003
)

// RVError wraps an underlying PCSC error code.
type RVError struct {
	RV uint32
}

// Error returns a string encoding of the error code. Note that human readable
// messages are not provided by this package, and are handled by the piv
// package instead.
func (r *RVError) Error() string {
	return fmt.Sprintf("rv 0x%x", r.RV)
}

// Client represents a connection with the pcscd process.
type Client struct {
	conn net.Conn
}

// Close releases the underlying connection. It does not release any contexts
// which must be closed separately.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) checkVersion() error {
	req := struct {
		Major int32
		Minor int32
		RV    uint32
	}{majorVersion, minorVersion, RVSuccess}
	if err := c.sendMessage(commandVersion, req, &req); err != nil {
		return fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: req.RV}
	}
	if req.Major != majorVersion {
		return fmt.Errorf("unsupported major version of pcscd protocol: %d", req.Major)
	}
	return nil
}

const (
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L286
	maxReaderNameSize = 128
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L59
	maxAttributeSize = 33
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L284
	maxReaders = 16
)

// readerState holds metadata about a PCSC card.
//
// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/eventhandler.h#L52
type readerState struct {
	Name         [maxReaderNameSize]byte
	EventCounter uint32
	State        uint32
	Sharing      int32

	Attr     [maxAttributeSize]byte
	AttrSize uint32
	Protocol uint32
}

func (r readerState) name() string {
	if r.Name[0] == 0x00 {
		return ""
	}
	i := len(r.Name)
	for ; i > 0; i-- {
		if r.Name[i-1] != 0x00 {
			break
		}
	}
	return string(r.Name[:i])
}

// Readers returns the names of all readers that are connected to the device.
func (c *Client) Readers() ([]string, error) {
	resp, err := c.readers()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, r := range resp {
		name := r.name()
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func (c *Client) readers() (states [maxReaders]readerState, err error) {
	if err := c.sendMessage(commandGetReadersState, nil, &states); err != nil {
		return states, fmt.Errorf("send message: %v", err)
	}
	return states, nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L118
type establishRequest struct {
	Scope   uint32
	Context uint32
	RV      uint32
}

// Context holds an open PCSC context, which is required to perform actions
// such as starting transactions or transmitting data to a card.
type Context struct {
	client  *Client
	context uint32
}

// NewContext attempts to establish a context with the PCSC daemon. The returned
// context is only valid while the client is open.
func (c *Client) NewContext() (*Context, error) {
	const scopeSystem = 0x0002
	req := establishRequest{
		Scope: scopeSystem,
		RV:    RVSuccess,
	}
	if err := c.sendMessage(commandEstablishContext, req, &req); err != nil {
		return nil, fmt.Errorf("establish context: %v", err)
	}
	if req.RV != RVSuccess {
		return nil, &RVError{RV: req.RV}
	}
	return &Context{client: c, context: req.Context}, nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L118
type releaseRequest struct {
	Context uint32
	RV      uint32
}

// Close releases the context with the PCSC daemon.
func (c *Context) Close() error {
	req := releaseRequest{
		Context: c.context,
		RV:      RVSuccess,
	}
	if err := c.client.sendMessage(commandReleaseContext, req, &req); err != nil {
		return fmt.Errorf("release context: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: req.RV}
	}
	return nil
}

// Connection represents a connection to a specific smartcard.
type Connection struct {
	client  *Client
	context uint32
	card    int32
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L141
type connectRequest struct {
	Context            uint32
	Reader             [maxReaderNameSize]byte
	ShareMode          uint32
	PreferredProtocols uint32
	Card               int32
	ActiveProtocols    uint32
	RV                 uint32
}

func (c *Context) Connect(reader string, mode uint32) (*Connection, error) {
	req := connectRequest{
		Context:            c.context,
		ShareMode:          Shared,
		PreferredProtocols: ProtocolT1,
		RV:                 RVSuccess,
	}

	if len(reader)+1 > maxReaderNameSize {
		return nil, fmt.Errorf("reader name too long")
	}
	copy(req.Reader[:], []byte(reader))

	if err := c.client.sendMessage(commandConnect, req, &req); err != nil {
		return nil, fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return nil, &RVError{RV: req.RV}
	}
	if req.Card == 0 {
		return nil, fmt.Errorf("card returned no value")
	}
	return &Connection{
		client: c.client, context: c.context, card: req.Card,
	}, nil
}

//https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L172
type disconnectRequest struct {
	Card        int32
	Disposition uint32
	RV          uint32
}

func (c *Connection) Close() error {
	req := disconnectRequest{
		Card:        c.card,
		Disposition: LeaveCard,
		RV:          RVSuccess,
	}

	if err := c.client.sendMessage(commandDisconnect, req, &req); err != nil {
		return fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: req.RV}
	}
	return nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L184
type beginRequest struct {
	Card int32
	RV   uint32
}

// BeginTransaction is called before transmitting data to the card.
func (c *Connection) BeginTransaction() error {
	req := beginRequest{
		Card: c.card,
		RV:   RVSuccess,
	}

	if err := c.client.sendMessage(commandBeginTransaction, req, &req); err != nil {
		return fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: req.RV}
	}
	return nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L195
type endRequest struct {
	Card        int32
	Disposition uint32
	RV          uint32
}

func (c *Connection) EndTransaction() error {
	req := endRequest{
		Card:        c.card,
		Disposition: LeaveCard,
		RV:          RVSuccess,
	}

	if err := c.client.sendMessage(commandEndTransaction, req, &req); err != nil {
		return fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: req.RV}
	}
	return nil
}

func (c *Connection) Transmit(b []byte) ([]byte, error) {
	return nil, nil
}

func (c *Client) sendMessage(command uint32, req, resp interface{}) error {
	var data []byte
	if req != nil {
		b := &bytes.Buffer{}
		if err := binary.Write(b, nativeByteOrder, req); err != nil {
			return fmt.Errorf("marshaling message body: %v", err)
		}

		size := uint32(b.Len())

		data = make([]byte, b.Len()+4+4)
		nativeByteOrder.PutUint32(data[0:4], size)
		nativeByteOrder.PutUint32(data[4:8], command)
		io.ReadFull(b, data[8:])
	} else {
		data = make([]byte, 4+4)
		nativeByteOrder.PutUint32(data[0:4], 0)
		nativeByteOrder.PutUint32(data[4:8], command)
	}

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("write request bytes: %v", err)
	}

	respData := &bytes.Buffer{}
	if err := binary.Read(io.TeeReader(c.conn, respData), nativeByteOrder, resp); err != nil {
		return fmt.Errorf("read response: %v", err)
	}

	fmt.Fprintln(os.Stderr, "Request:")
	fmt.Fprintln(os.Stderr, hex.Dump(data[8:]))

	fmt.Fprintln(os.Stderr, "Response:")
	fmt.Fprintln(os.Stderr, hex.Dump(respData.Bytes()))
	return nil
}

// Config is used to modify client behavior.
type Config struct {
	// SocketPath can be used to override a path to the pcscd socket. This field
	// is generally not required unless pcscd has been compiled with modified
	// options.
	//
	// This value defaults to the pcsclite behavior, preferring the value of the
	// PCSCLITE_CSOCK_NAME environment variable then defaulting to
	// "/run/pcscd/pcscd.comm".
	SocketPath string
}

// NewClient attempts to initialize a connection with pcscd. The context is used
// for dialing the unix domain socket.
func NewClient(ctx context.Context, c *Config) (*Client, error) {
	p := c.SocketPath
	if p == "" {
		p = os.Getenv(pcscSocketPathEnv)
	}
	if p == "" {
		p = pcscSocketPath
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", p)
	if err != nil {
		return nil, fmt.Errorf("dial unix socket: %v", err)
	}
	client := &Client{conn: conn}
	if err := client.checkVersion(); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}
