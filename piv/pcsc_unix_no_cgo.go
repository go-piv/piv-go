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

// +build !cgo pcscgo
// +build linux freebsd

package piv

import (
	"context"
	"errors"

	"github.com/go-piv/piv-go/piv/internal/pcsc"
)

func scCheck(err error) error {
	var e *pcsc.RVError
	if errors.As(err, &e) {
		return &scErr{int64(e.RV)}
	}
	return err
}

const rcSuccess = pcsc.RVSuccess

type scContext struct {
	client *pcsc.Client
	ctx    *pcsc.Context
}

func newSCContext() (*scContext, error) {
	c, err := pcsc.NewClient(context.Background(), &pcsc.Config{})
	if err != nil {
		return nil, err
	}
	ctx, err := c.NewContext(pcsc.Exclusive)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &scContext{c, ctx}, nil
}

func (c *scContext) Close() error {
	err1 := c.ctx.Close()
	if err := c.client.Close(); err != nil {
		return err
	}
	return err1
}

func (c *scContext) ListReaders() ([]string, error) {
	return c.client.Readers()
}

type scHandle struct {
}

func (c *scContext) Connect(reader string) (*scHandle, error) {
	return nil, nil
}

func (h *scHandle) Close() error {
	return nil
}

type scTx struct {
}

func (h *scHandle) Begin() (*scTx, error) {
	return nil, nil
}

func (t *scTx) Close() error {
	return nil
}

func (t *scTx) transmit(req []byte) (more bool, b []byte, err error) {
	return false, nil, nil
}
