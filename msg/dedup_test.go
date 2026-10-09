package msg

// Tests for the carrier_dedup additive fields (SPEC-CLUSTER21 §1).
//
// The version-safety argument of the whole negotiation rests on two properties
// of plain encoding/json, so they are pinned here rather than argued: an old
// binary reading a new wire ignores the new booleans, and a new binary reading
// an old wire (or any future one with unknown fields) decodes them as zero and
// ignores the rest. Neither direction needs the capability exchange.

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDedupFieldsMarshalByDefault marshals both proposal and ack and checks
// the fields ride the default marshaling -- no omitempty, so an explicit
// "Dedup":false on the wire is a statement ("this binary knows the field and
// is not proposing"), not an accident.
func TestDedupFieldsMarshalByDefault(t *testing.T) {
	regPxy, err := json.Marshal(&RegProxy{ClientId: "c", Secret: "s", Dedup: true})
	if err != nil {
		t.Fatalf("marshal RegProxy: %v", err)
	}
	if !strings.Contains(string(regPxy), `"Dedup":true`) {
		t.Fatalf("RegProxy did not marshal the Dedup proposal: %s", regPxy)
	}

	startPxy, err := json.Marshal(&StartProxy{Url: "http://x", DedupAck: true})
	if err != nil {
		t.Fatalf("marshal StartProxy: %v", err)
	}
	if !strings.Contains(string(startPxy), `"DedupAck":true`) {
		t.Fatalf("StartProxy did not marshal the DedupAck ack: %s", startPxy)
	}
}

// TestDedupFieldsAbsentOnTheWireDecodeFalse is the old-peer direction: a
// binary that predates carrier_dedup never emits the fields, and the new
// binary must read such a message as "no proposal" / "no ack" -- the zero
// value -- without any special case.
func TestDedupFieldsAbsentOnTheWireDecodeFalse(t *testing.T) {
	var regPxy RegProxy
	if err := json.Unmarshal([]byte(`{"ClientId":"c","Secret":"s"}`), &regPxy); err != nil {
		t.Fatalf("unmarshal old-wire RegProxy: %v", err)
	}
	if regPxy.Dedup {
		t.Fatal("RegProxy decoded a Dedup proposal from a wire that does not carry the field")
	}

	var startPxy StartProxy
	if err := json.Unmarshal([]byte(`{"Url":"http://x","ClientAddr":"1.2.3.4:5"}`), &startPxy); err != nil {
		t.Fatalf("unmarshal old-wire StartProxy: %v", err)
	}
	if startPxy.DedupAck {
		t.Fatal("StartProxy decoded a DedupAck from a wire that does not carry the field")
	}
}

// TestDedupFieldsSurviveUnknownPeers is the other half of version safety: the
// fields must survive a peer that adds its OWN unknown fields (a future
// binary), and a new binary must ignore fields IT does not know -- default
// unmarshaling does both.
func TestDedupFieldsSurviveUnknownPeers(t *testing.T) {
	var regPxy RegProxy
	wire := `{"ClientId":"c","Secret":"s","Dedup":true,"SomeFutureField":42}`
	if err := json.Unmarshal([]byte(wire), &regPxy); err != nil {
		t.Fatalf("unmarshal future-wire RegProxy: %v", err)
	}
	if !regPxy.Dedup {
		t.Fatal("the Dedup proposal did not survive a peer's unknown fields")
	}

	var startPxy StartProxy
	wire = `{"Url":"http://x","DedupAck":true,"AnotherFutureField":"x"}`
	if err := json.Unmarshal([]byte(wire), &startPxy); err != nil {
		t.Fatalf("unmarshal future-wire StartProxy: %v", err)
	}
	if !startPxy.DedupAck {
		t.Fatal("the DedupAck did not survive a peer's unknown fields")
	}
}
