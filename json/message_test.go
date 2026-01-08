package json

import (
	"testing"
)

func TestMessageMarshalJSON(t *testing.T) {
	var nilMsg Message

	got, err := nilMsg.MarshalJSON()
	if err != nil {
		t.Fatalf("nil message marshal returned error: %v", err)
	}
	if string(got) != "null" {
		t.Fatalf("nil message marshal = %q, want %q", string(got), "null")
	}

	msg := Message(`{"ok":true}`)
	got, err = msg.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal returned error: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("marshal = %q, want %q", string(got), string(msg))
	}
}

func TestMessageUnmarshalJSON(t *testing.T) {
	src := []byte(`{"count":1}`)

	var msg Message
	if err := msg.UnmarshalJSON(src); err != nil {
		t.Fatalf("unmarshal returned error: %v", err)
	}
	if string(msg) != string(src) {
		t.Fatalf("unmarshal = %q, want %q", string(msg), string(src))
	}

	src[0] = 'X'
	if string(msg) == string(src) {
		t.Fatalf("unmarshal reused source backing array")
	}
}

func TestMessageUnmarshalJSONNilReceiver(t *testing.T) {
	var msg *Message

	if err := msg.UnmarshalJSON([]byte("null")); err == nil {
		t.Fatal("expected error when unmarshalling into nil receiver")
	}
}
