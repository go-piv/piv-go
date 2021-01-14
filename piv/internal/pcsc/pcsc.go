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

package pcsc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

var nativeByteOrder binary.ByteOrder

const (
	pcscSocketPathEnv = "PCSCLITE_CSOCK_NAME"
	pcscSocketPath    = "/run/pcscd/pcscd.comm"
)

const (
	scardSSuccess = 0

	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L76
	commandVersion         = 0x11
	commandGetReadersState = 0x12
)

type Client struct {
	conn net.Conn
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) version() (major, minor int32, err error) {
	req := struct {
		Major int32
		Minor int32
		RV    uint32
	}{4, 4, scardSSuccess}

	var resp struct {
		Major int32
		Minor int32
		RV    uint32
	}
	if err := c.sendMessage(commandVersion, req, &resp); err != nil {
		return 0, 0, fmt.Errorf("send message: %v", err)
	}
	if resp.RV != scardSSuccess {
		return 0, 0, fmt.Errorf("invalid response value: %x", resp.RV)
	}
	return resp.Major, resp.Minor, nil
}

const (
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L286
	maxReaderNameSize = 128
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L59
	maxAttributeSize = 33
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L284
	maxReaders = 16
)

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/eventhandler.h#L52
// 	typedef struct pubReaderStatesList
// 	{
// 		char readerName[MAX_READERNAME]; /**< reader name */
// 		uint32_t eventCounter; /**< number of card events */
// 		uint32_t readerState; /**< SCARD_* bit field */
// 		int32_t readerSharing; /**< PCSCLITE_SHARING_* sharing status */
//
// 		UCHAR cardAtr[MAX_ATR_SIZE]; /**< ATR */
// 		uint32_t cardAtrLength; /**< ATR length */
// 		uint32_t cardProtocol; /**< SCARD_PROTOCOL_* value */
// 	}
// 	READER_STATE;

type readerState struct {
	Name         [maxReaderNameSize]byte
	EventCounter uint32
	State        uint32
	Sharing      uint32

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

func (c *Client) readers() ([]string, error) {
	var resp [maxReaders]readerState

	if err := c.sendMessage(commandGetReadersState, nil, &resp); err != nil {
		return nil, fmt.Errorf("send message: %v", err)
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

	if err := binary.Read(c.conn, nativeByteOrder, resp); err != nil {
		return fmt.Errorf("read response: %v", err)
	}
	return nil
}

type Config struct {
	SocketPath string
}

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
	return &Client{
		conn: conn,
	}, nil
}
