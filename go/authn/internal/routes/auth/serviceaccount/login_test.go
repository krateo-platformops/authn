package serviceaccount

import (
	"net/http"
	"testing"
)

func TestParseServiceAccountUsername(t *testing.T) {
	cases := []struct {
		in       string
		ns, name string
		wantErr  bool
	}{
		{"system:serviceaccount:krateo-system:composition-dynamic-controller", "krateo-system", "composition-dynamic-controller", false},
		{"system:serviceaccount:default:rdc", "default", "rdc", false},
		{"system:serviceaccount:ns:name:extra", "ns", "name:extra", false}, // SplitN keeps the remainder as name
		{"alice", "", "", true},                        // not an SA
		{"system:serviceaccount:onlyns", "", "", true}, // missing name
		{"system:serviceaccount::name", "", "", true},  // empty namespace
		{"system:serviceaccount:ns:", "", "", true},    // empty name
	}
	for _, c := range cases {
		ns, name, err := parseServiceAccountUsername(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if ns != c.ns || name != c.name {
			t.Errorf("%q: got (%q,%q), want (%q,%q)", c.in, ns, name, c.ns, c.name)
		}
	}
}

func TestContainsAudience(t *testing.T) {
	if !containsAudience([]string{"a", "authn", "b"}, "authn") {
		t.Error("expected audience found")
	}
	if containsAudience([]string{"a", "b"}, "authn") {
		t.Error("expected audience not found")
	}
	if containsAudience(nil, "authn") {
		t.Error("nil audiences should not match")
	}
}

func TestBearerToken(t *testing.T) {
	mk := func(h string) *http.Request {
		r, _ := http.NewRequest(http.MethodPost, "/serviceaccount/login", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		return r
	}
	if tok, ok := bearerToken(mk("Bearer abc.def")); !ok || tok != "abc.def" {
		t.Errorf("valid bearer: tok=%q ok=%v", tok, ok)
	}
	if tok, ok := bearerToken(mk("bearer xyz")); !ok || tok != "xyz" { // case-insensitive scheme
		t.Errorf("lowercase scheme: tok=%q ok=%v", tok, ok)
	}
	if _, ok := bearerToken(mk("Basic abc")); ok {
		t.Error("Basic must not parse as Bearer")
	}
	if _, ok := bearerToken(mk("")); ok {
		t.Error("missing header must not parse")
	}
	if _, ok := bearerToken(mk("Bearer ")); ok {
		t.Error("empty token must not parse")
	}
}
