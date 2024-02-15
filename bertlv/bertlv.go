package bertlv

import (
	"fmt"
)

const (
	// dataLongLen is the value that the data length is set to if data is > 254 bytes.
	// nolint:unused
	dataLongLen = 0xFF

	// tagMaskValue is used to mask off the bits that are not part of the tag value.
	tagMaskValue = 0x03

	// classMaskValue is used to mask off the bits that are not part of the class value.
	classMaskValue = 0x20

	// longTagMaskValue is used to determine if we have a long tag.
	longTagMaskValue = 0x1F

	// longTagInitialLen is the minimum length of a long tag.
	longTagInitialLen = 0x80

	sevenBitMask = 0x7f

	highBitMask = 0x80
)

type TLVData map[string][]byte

// tlv is a helper for decoding the BER-TLV data that is found in the OpenPGP card spec.
type tlv struct {
	// data contains the slice of data seen so far.
	data []byte
	// values is a pointer to the entire map.
	// This is a pointer because it is recursively passed down to be updated as the BER fields are parsed.
	values *TLVData

	// debug can be enabled for dumping information
	debug bool
}

var ErrNoBytesLeft = fmt.Errorf("no bytes left")

// Parse takes a byte array of data of BER-TLV encoded data to decode into values.
// If values is nil, it will be created.
// A created map or an error will be returned upon completion.
func Parse(data []byte, values *TLVData) (*TLVData, error) {
	if values == nil {
		values = &TLVData{}
	}

	return newTlv(data, values).parseBer("")
}

func (t *tlv) EnableDebug() {
	t.debug = true
}

func (t *tlv) DisableDebug() {
	t.debug = false
}

// newTlv is a private function to create a new tlv structure.
// This is called for each segment of data, and will decode that subset to the values map.
// values will contain keys for each segment of data that was decoded when decoding is complete.
// nolint:varnamelen
func newTlv(data []byte, values *TLVData) *tlv {
	if values == nil {
		values = &TLVData{}
	}

	t := &tlv{
		data:   make([]byte, len(data)),
		values: values,
		debug:  false,
	}

	copy(t.data, data)

	return t
}

// getByte will return a single byte as a uint16.
func (t *tlv) getByte() (uint16, error) {
	if len(t.data) == 0 {
		return 0, ErrNoBytesLeft
	}

	v := t.data[0]
	t.data = t.data[1:]

	return uint16(v), nil
}

// getBytes will return n bytes.
// nolint:varnamelen
func (t *tlv) getBytes(n uint16) ([]byte, error) {
	if len(t.data) < int(n) {
		return nil, ErrNoBytesLeft
	}

	v := t.data[:n]
	t.data = t.data[n:]

	return v, nil
}

// key converts a tag and optional prefix into a key for the map.
// They key is 6F, or 6F.AB, or 6F.AB.A3.
func (t *tlv) key(prefix string, tag uint16) string {
	if prefix != "" {
		prefix += "."
	}

	return fmt.Sprintf("%s%02X", prefix, tag)
}

// setValue will set a specific value in the map based on the prefix and tag presented.
func (t *tlv) setValue(prefix string, tag uint16, dataLen uint16) ([]byte, error) {
	key := t.key(prefix, tag)

	value, err := t.getBytes(dataLen)
	if err != nil {
		return nil, err
	}

	(*t.values)[key] = value

	return value, nil
}

// parseSimple is not used and was lifted from the python.
// nolint:unused
func (t *tlv) parseSimple(prefix string) (*TLVData, error) {
	for {
		if len(t.data) == 0 {
			return t.values, nil
		}

		tag, err := t.getByte()
		if err != nil {
			return t.values, err
		}

		dataLen, err := t.getByte()
		if err != nil {
			return t.values, err
		}

		if dataLen == dataLongLen {
			var (
				highByte uint16
				lowByte  uint16
			)

			highByte, err = t.getByte()
			if err != nil {
				return t.values, err
			}

			lowByte, err = t.getByte()
			if err != nil {
				return t.values, err
			}

			// nolint:gomnd
			dataLen = highByte<<8 | lowByte
		}

		_, err = t.setValue(prefix, tag, dataLen)
		if err != nil {
			return t.values, err
		}
	}
}

// parseBer will recursively parse for a given prefix and populate.
// nolint: cyclop,funlen,gocognit
func (t *tlv) parseBer(prefix string) (*TLVData, error) {
	for {
		if len(t.data) == 0 {
			return t.values, nil
		}

		tag, err := t.getByte()
		if err != nil {
			return t.values, err
		}

		// I do not know what classValue is used for, so ignore it.
		// nolint:gomnd
		classValue := (tag >> 6) & tagMaskValue
		_ = classValue

		isConstructed := tag&classMaskValue == classMaskValue

		if tag&longTagMaskValue == longTagMaskValue {
			// long tag (more than a single byte)
			tagByte := uint16(longTagInitialLen)

			for {
				if tagByte&longTagInitialLen != longTagInitialLen {
					break
				}

				tagByte, err = t.getByte()
				if err != nil {
					return t.values, err
				}

				// nolint:gomnd
				tag = (tag << 7) + (tagByte & sevenBitMask)
			}
		}

		dataLenByte, err := t.getByte()
		if err != nil {
			return t.values, err
		}

		dataLen := uint16(0)
		if dataLenByte&highBitMask == 0 {
			// short length
			dataLen = dataLenByte
		} else {
			// long length
			for i := uint16(0); i < dataLenByte&sevenBitMask; i++ {
				// nolint:gomnd
				var (
					highByte = dataLen << 8
					lowByte  uint16
				)

				lowByte, err = t.getByte()
				if err != nil {
					return t.values, err
				}

				dataLen = highByte + lowByte
			}
		}

		value, err := t.setValue(prefix, tag, dataLen)
		if err != nil {
			return t.values, err
		}

		if isConstructed {
			nextTlv := newTlv(value, t.values)

			_, err = nextTlv.parseBer(t.key(prefix, tag))
			if err != nil {
				return nil, err
			}
		}
	}
}
