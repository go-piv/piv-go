package bertlv

import (
	"encoding/json"
	"fmt"
)

// MakeJSONString dumps a struct to json as a helper.
func MakeJSONString(data interface{}) string {
	prettifiedOSJSON, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return fmt.Sprintf(`{ "error": "%s"}`, err.Error())
	}

	return string(prettifiedOSJSON)
}
