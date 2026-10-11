package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// MaxWriteBody bounds the JSON body of every write (policies, approve and
// reject, learning mode, allowlisting an event). An allowlist entry is a
// few hundred bytes; 64 KiB leaves room for long glob lists.
const MaxWriteBody = 64 << 10

// decodeBody reads one JSON value from a request body of at most
// MaxWriteBody bytes into v. With strict, unknown fields are an error.
// Trailing data after the value is an error. On failure it answers the
// request (413 for a body over the limit, 400 otherwise, prefixed with
// what) and returns false.
func decodeBody(w http.ResponseWriter, r *http.Request, v any, strict bool, what string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxWriteBody))
	if strict {
		dec.DisallowUnknownFields()
	}
	err := dec.Decode(v)
	if err == nil {
		switch err = dec.Decode(&json.RawMessage{}); {
		case err == io.EOF:
			err = nil
		case err == nil:
			err = errors.New("unexpected data after the JSON value")
		}
	}
	if err == nil {
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body is larger than %d bytes", MaxWriteBody))
		return false
	}
	writeError(w, http.StatusBadRequest, fmt.Sprintf("%s: %v", what, err))
	return false
}
