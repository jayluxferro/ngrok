package policy

import (
	"sort"
	"strings"
	"testing"
)

// These tests are about the message an operator gets when they name an action
// this build does not implement in a phase: "... (this build implements X, Y,
// Z)". That list is a promise about the engine, and it is the only thing an
// operator has to go on when the document they wrote came from ngrok's docs
// instead of this build's. It used to be a second, hand-written list beside the
// actionPhases matrix, which is a promise that can go stale without anything
// failing; it is now derived from the matrix, and this file pins the two halves
// of the contract that derivation is supposed to give.

// minimalConfig is the smallest config that makes each action's validation
// pass, so that "the message claims this action works here" can be checked by
// actually compiling one.
var minimalConfig = map[string]map[string]interface{}{
	ActionAddHeaders:     {"headers": map[string]interface{}{"X-Probe": "1"}},
	ActionRemoveHeaders:  {"headers": []interface{}{"X-Probe"}},
	ActionDeny:           nil,
	ActionCustomResponse: nil, // status defaults; the point is that it compiles
	ActionLog:            {"metadata": map[string]interface{}{"probe": "1"}},
	ActionSetVars:        {"vars": []interface{}{map[string]interface{}{"probe": "1"}}},
	ActionRestrictIPs:    {"enforce": true, "allow": []interface{}{"127.0.0.0/8"}},
	// The auth actions (SPEC-CLUSTER6): each needs the one field its validator
	// requires. jwks_uri is only shape-checked here; nothing is fetched.
	ActionBasicAuth:     {"credentials": []interface{}{"probe:probe"}},
	ActionBearerAuth:    {"tokens": []interface{}{"probe"}},
	ActionAPIKeyAuth:    {"keys": []interface{}{"probe"}},
	ActionJWTValidation: {"jwks_uri": "https://idp.example/jwks.json"},
	// The webhook verification action (SPEC-CLUSTER10): its two required
	// fields. The secret is inline here; the vault round-trip is
	// webhook_test.go's.
	ActionWebhookVerification: {"provider": "stripe", "secrets": []interface{}{"probe"}},
	// The oidc action (SPEC-CLUSTER18): its three required fields. Like
	// jwks_uri, the issuer is only shape-checked here; nothing is fetched at
	// compile, and the flow is oidc_test.go's.
	ActionOIDC: {"issuer": "https://idp.example", "client_id": "probe", "client_secret": "probe"},
}

// TestPhaseActionsMatchesTheMatrix is the first half: the list the message
// renders is the sorted set of actions the phase matrix actually implements for
// that phase. Deriving both sides from the matrix means this cannot catch a
// matrix that is itself wrong -- it catches the drift this replaces, a list
// maintained by hand beside the table that no longer agrees with it.
func TestPhaseActionsMatchesTheMatrix(t *testing.T) {
	for _, p := range []phase{phaseConnect, phaseRequest, phaseResponse} {
		got := phaseActions(p)

		if !sort.StringsAreSorted(got) {
			t.Errorf("phaseActions(%s) = %v is not sorted, so the message it renders is not deterministic", p, got)
		}

		var want []string
		for name, phases := range actionPhases {
			for _, ph := range phases {
				if ph == p {
					want = append(want, name)
				}
			}
		}
		sort.Strings(want)

		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("phaseActions(%s) = %v, but the phase matrix implements %v there", p, got, want)
		}
	}
}

// TestPhaseActionsAreImplemented is the second half, and the one that is not a
// restatement of the implementation: every action the message claims for a
// phase is compiled in that phase, so the message cannot promise something the
// engine refuses. A list that under-claims is merely unhelpful; a list that
// over-claims sends an operator to write a document that then fails to load for
// a reason the error message told them was fine.
func TestPhaseActionsAreImplemented(t *testing.T) {
	set := func(p phase, tp *TrafficPolicy, a *Action) {
		switch p {
		case phaseConnect:
			tp.OnTCPConnect = []*Action{a}
		case phaseRequest:
			tp.OnHTTPRequest = []*Action{a}
		case phaseResponse:
			tp.OnHTTPResponse = []*Action{a}
		}
	}

	for _, p := range []phase{phaseConnect, phaseRequest, phaseResponse} {
		for _, name := range phaseActions(p) {
			cfg, known := minimalConfig[name]
			if !known {
				t.Fatalf("no minimal config for %s: an action was added to the matrix without a probe here", name)
			}

			tp := new(TrafficPolicy)
			set(p, tp, &Action{Name: name, Config: cfg})
			if _, err := tp.Compile(); err != nil {
				t.Errorf("%s says it implements %s, but compiling one there failed: %v", p, name, err)
			}
		}
	}
}

// TestUnknownActionMessageNamesThePhase is the end-to-end shape of both halves:
// the error an operator actually sees for a rule that names no action and for
// one that names an action this build does not have.
func TestUnknownActionMessageNamesThePhase(t *testing.T) {
	tp := &TrafficPolicy{
		OnHTTPRequest: []*Action{
			{Name: "restrict", Config: map[string]interface{}{}},
		},
	}
	_, err := tp.Compile()
	if err == nil {
		t.Fatalf("an action this build does not implement must not compile")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown action") {
		t.Fatalf("expected the message to say the action is unknown, got: %v", err)
	}
	// The on_http_request phase's list, in sorted order, rendered into the
	// message: the operator can copy a name out of it.
	if want := strings.Join(phaseActions(phaseRequest), ", "); !strings.Contains(msg, want) {
		t.Errorf("the message does not name what on_http_request implements (%q): %v", want, err)
	}
	// The connect-only action is not offered for a request rule, because it
	// cannot run there.
	if strings.Contains(msg, ActionRestrictIPs) {
		t.Errorf("the message offers restrict-ips for on_http_request, where it does not run: %v", err)
	}

	tp = &TrafficPolicy{OnHTTPRequest: []*Action{{Config: map[string]interface{}{}}}}
	_, err = tp.Compile()
	if err == nil {
		t.Fatalf("a rule with no action name must not compile")
	}
	if !strings.Contains(err.Error(), "action has no name") || !strings.Contains(err.Error(), "on_http_request") {
		t.Errorf("expected the message to name the rule and the phase, got: %v", err)
	}
}
