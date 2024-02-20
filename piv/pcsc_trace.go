// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package piv

import (
	"context"
	"reflect"
)

// ClientTrace is a set of hooks to run at various stages pcsc calls.
// Any particular hook may be nil. Functions may be
// called concurrently from different goroutines and some may be called
// after the request has completed or failed.
//
// ClientTrace is adapted from httptrace.ClientTrace.
// ClientTrace currently traces a single pcsc call, providing the apdus
// that were sent.
type ClientTrace struct {
	// Transmit is called before an APDU is transmitted to the card.
	// The byte array is the complete contents of the request being sent to
	// SCardTransmit.
	// Transmit is called from scTx.
	Transmit func(req []byte)

	// TransmitResult is called afterr an APDU is transmitted to the card.
	// req is the contents of the request.
	// resp is the contents of the response.
	// respN is the number of bytes returned in the response.
	// s1,sw2 are the last 2 bytes of the response.
	// sw1,sw2 are the contents of last 2 bytes of the response.
	// an apduErr contains sw1,sw2.
	// if sw1==0x61, there is more data.
	// TransmitResult is called from scTx.
	TransmitResult func(req, resp []byte, respN int, sw1, sw2 byte)
}

// unique type to prevent assignment.
type clientEventContextKey struct{}

// ContextClientTrace returns the [ClientTrace] associated with the
// provided context. If none, it returns nil.
func ContextClientTrace(ctx context.Context) *ClientTrace {
	trace, _ := ctx.Value(clientEventContextKey{}).(*ClientTrace)
	return trace
}

// compose modifies t such that it respects the previously-registered hooks in old,
// subject to the composition policy requested in t.Compose.
func (t *ClientTrace) compose(old *ClientTrace) {
	if old == nil {
		return
	}
	tv := reflect.ValueOf(t).Elem()
	ov := reflect.ValueOf(old).Elem()
	structType := tv.Type()
	for i := 0; i < structType.NumField(); i++ {
		tf := tv.Field(i)
		hookType := tf.Type()
		if hookType.Kind() != reflect.Func {
			continue
		}
		of := ov.Field(i)
		if of.IsNil() {
			continue
		}
		if tf.IsNil() {
			tf.Set(of)
			continue
		}

		// Make a copy of tf for tf to call. (Otherwise it
		// creates a recursive call cycle and stack overflows)
		tfCopy := reflect.ValueOf(tf.Interface())

		// We need to call both tf and of in some order.
		newFunc := reflect.MakeFunc(hookType, func(args []reflect.Value) []reflect.Value {
			tfCopy.Call(args)
			return of.Call(args)
		})
		tv.Field(i).Set(newFunc)
	}
}

// WithClientTrace returns a new context based on the provided parent
// ctx. HTTP client requests made with the returned context will use
// the provided trace hooks, in addition to any previous hooks
// registered with ctx. Any hooks defined in the provided trace will
// be called first.
func WithClientTrace(ctx context.Context, trace *ClientTrace) context.Context {
	if trace == nil {
		panic("nil trace")
	}
	old := ContextClientTrace(ctx)
	trace.compose(old)

	ctx = context.WithValue(ctx, clientEventContextKey{}, trace)

	return ctx
}
