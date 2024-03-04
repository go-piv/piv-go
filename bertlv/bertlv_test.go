package bertlv

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

//prefix: , data: {"d": "0", "prefix": "", "data": [101, 9, 91, 0, 95, 45, 0, 95, 53, 1, 57], "tvdict": {}}
//prefix: 65., data: {"d": "0", "prefix": "65.", "data": [91, 0, 95, 45, 0, 95, 53, 1, 57], "tvdict": {"65": [91, 0, 95, 45, 0, 95, 53, 1, 57]}}
//prefix: 65., data: {"d": "1", "prefix": "65.", "data": [], "tvdict": {"65": [91, 0, 95, 45, 0, 95, 53, 1, 57], "65.5B": [], "65.2FAD": [], "65.2FB5": [57]}}
//prefix: , data: {"d": "1", "prefix": "", "data": [], "tvdict": {"65": [91, 0, 95, 45, 0, 95, 53, 1, 57], "65.5B": [], "65.2FAD": [], "65.2FB5": [57]}}
//
//prefix: , data: {"d": "0", "prefix": "", "data": [101, 9, 91, 0, 95, 45, 0, 95, 53, 1, 57], "tvdict": {}}
//prefix:  tag: 65
//prefix:  myclass: 01
//prefix:  isconstructed: 20
//prefix:  len: 09
//prefix:  len: 09
//prefix:  value: 5B 00 5F 2D 00 5F 35 01 39
//prefix: 65., data: {"d": "0", "prefix": "65.", "data": [91, 0, 95, 45, 0, 95, 53, 1, 57], "tvdict": {"65": [91, 0, 95, 45, 0, 95, 53, 1, 57]}}
//prefix: 65. tag: 5B
//prefix: 65. myclass: 01
//prefix: 65. isconstructed: 00
//prefix: 65. len: 00
//prefix: 65. len: 00
//prefix: 65. value:
//prefix: 65. tag: 5F
//prefix: 65. myclass: 01
//prefix: 65. isconstructed: 00
//prefix: 65. longtag
//prefix: 65. tag: 2FAD
//prefix: 65. tag: 2FAD
//prefix: 65. len: 00
//prefix: 65. len: 00
//prefix: 65. value:
//prefix: 65. tag: 5F
//prefix: 65. myclass: 01
//prefix: 65. isconstructed: 00
//prefix: 65. longtag
//prefix: 65. tag: 2FB5
//prefix: 65. tag: 2FB5
//prefix: 65. len: 01
//prefix: 65. len: 01
//prefix: 65. value: 39
//prefix: 65., data: {"d": "1", "prefix": "65.", "data": [], "tvdict": {"65": [91, 0, 95, 45, 0, 95, 53, 1, 57], "65.5B": [], "65.2FAD": [], "65.2FB5": [57]}}
//prefix: , data: {"d": "1", "prefix": "", "data": [], "tvdict": {"65": [91, 0, 95, 45, 0, 95, 53, 1, 57], "65.5B": [], "65.2FAD": [], "65.2FB5": [57]}}

// nolint:goerr113
func check(key string, data, expected map[string][]byte) error {
	d, dok := data[key]
	e, eok := expected[key]

	if dok != eok {
		return fmt.Errorf("failed: data[%s][%t] != expected[%s][%t]", key, dok, key, eok)
	}

	// nolint:gosimple  // bytes.Equal does not behave the same here.
	if bytes.Compare(d, e) != 0 {
		return fmt.Errorf("failed: data[%s][%s] != expected[%s][%s]", key, hex.EncodeToString(d), key, hex.EncodeToString(e))
	}

	return nil
}

func Test_simple(t *testing.T) {
	t.Parallel()

	data := []byte{101, 9, 91, 0, 95, 45, 0, 95, 53, 1, 57}
	expectedMap := map[string][]byte{
		"65":      {91, 0, 95, 45, 0, 95, 53, 1, 57},
		"65.5B":   {},
		"65.2FAD": {},
		"65.2FB5": {57},
	}

	parsed, _ := Parse(data, nil)

	for _, k := range []string{"65", "65.5B", "65.2FAD", "65.2FB5"} {
		if err := check(k, *parsed, expectedMap); err != nil {
			t.Errorf("%v", err)
			t.Fail()
		}
	}
}
