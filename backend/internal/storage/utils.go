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

func MarshalJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}