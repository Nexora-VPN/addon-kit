package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// noDuplicateKeys refuses a JSON document that names one key twice in any
// object. Decoding into a map keeps the last of them and decoding into a
// struct merges them, so with duplicates the signature (over the map) and
// the manifest a panel acts on (the struct) would be two different
// documents: content could be added to a signed manifest without breaking
// its signature.
func noDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkValue(dec); err != nil {
		var dup duplicateKey
		if errors.As(err, &dup) {
			return err
		}
		// %v, not %w: a truncated manifest is a bad manifest, never io.EOF.
		return fmt.Errorf("the manifest is not a JSON object: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("the manifest has more after its JSON object")
	}
	return nil
}

// duplicateKey is a key named twice in one object.
type duplicateKey string

func (k duplicateKey) Error() string {
	return fmt.Sprintf("the manifest names the key %q twice in one object", string(k))
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := k.(string)
			if seen[key] {
				return duplicateKey(key)
			}
			seen[key] = true
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}
