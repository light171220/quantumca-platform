package storage

import (
	"encoding/json"
	"fmt"
)

func UnmarshalJSON(data []byte, v interface{}) error {
	if len(data) == 0 {
		return fmt.Errorf("empty JSON data")
	}
	return json.Unmarshal(data, v)
}

func MarshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}