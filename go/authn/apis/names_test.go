package apis

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/krateo-platformops/plumbing/kubeutil"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// The User and ServiceAccount CRDs reject, at create, a name authn would
// rewrite when it names the user's Secret (#140). These are the rule's parts as
// the CRDs must carry them; the tests below prove the pattern is exactly the
// set of names plumbing's transform leaves unchanged, and that the generated
// CRDs (and the chart's copies) carry this rule, so neither can drift.
const (
	namePattern = `^[a-z0-9][-a-z0-9]{0,62}$`
	nameRule    = `oldSelf.hasValue() || self.metadata.name.matches('` + namePattern + `')`
	nameMessage = "the name must be a lowercase DNS-1123 label of at most 63 characters " +
		"(a-z, 0-9, '-', starting with a letter or digit): authn names the user's Secret " +
		"after it, and would rewrite any other name"
)

var nameRE = regexp.MustCompile(namePattern)

// unchanged is what the rule stands for: the Secret is named after the name
// itself. An object name is never empty, and the empty string, which the
// transform also leaves unchanged, is not a name the rule can see.
func unchanged(name string) bool {
	return name != "" && kubeutil.MakeDNS1123Compatible(name) == name
}

func TestNamePatternIsTheTransformsFixedPoints(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"alice", true},
		{"alice-smith", true},
		{"a", true},
		{"0", true},
		{"9lives", true},
		{"a--b", true},
		// The transform keeps a trailing '-'; the apiserver's own name
		// validation (a DNS-1123 subdomain) refuses it before the rule runs.
		{"alice-", true},
		{"alice.smith", false},
		{"Alice", false},
		{"ALICE", false},
		{"alice_smith", false},
		{"alice@example.com", false},
		{"-alice", false},
		{"--alice", false},
		{".alice", false},
		{"alice smith", false},
		{"élodie", false},
		{"Klvin", false}, // KELVIN SIGN, which lowercases to an ASCII 'k'
		{"alice\x00", false},
		{"\xff", false},
		{strings.Repeat("a", 62), true},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), false},
		{strings.Repeat("a", 253), false},
		{"", false},
	} {
		if got := nameRE.MatchString(tc.name); got != tc.want {
			t.Errorf("pattern on %q = %v, want %v", tc.name, got, tc.want)
		}
		if got := unchanged(tc.name); got != tc.want {
			t.Errorf("transform leaves %q unchanged = %v, want %v (it gives %q)",
				tc.name, got, tc.want, kubeutil.MakeDNS1123Compatible(tc.name))
		}
	}
}

// Generated names, drawn mostly from the characters the transform keeps, so
// that a good share of them match, with every kind of character it rewrites
// mixed in, and lengths across the 63-character cut.
func TestNamePatternAgreesWithTheTransformOnGeneratedNames(t *testing.T) {
	keep := []rune("abcdefghijklmnopqrstuvwxyz0123456789-")
	rewrite := []rune("ABCZ._@ :/+~\x00éKßİ\U0001F600�")
	rnd := rand.New(rand.NewSource(140))
	matched := 0
	const n = 50000
	for i := 0; i < n; i++ {
		length := rnd.Intn(70)
		if rnd.Intn(4) == 0 {
			length = 60 + rnd.Intn(8)
		}
		var b strings.Builder
		for j := 0; j < length; j++ {
			if rnd.Intn(40) == 0 {
				b.WriteRune(rewrite[rnd.Intn(len(rewrite))])
			} else {
				b.WriteRune(keep[rnd.Intn(len(keep))])
			}
		}
		s := b.String()
		if rnd.Intn(100) == 0 {
			s += "\xff" // invalid UTF-8
		}
		got, want := nameRE.MatchString(s), unchanged(s)
		if got != want {
			t.Fatalf("pattern on %q = %v, transform leaves it unchanged = %v", s, got, want)
		}
		if got {
			matched++
		}
	}
	// Both sides must be exercised, or the loop proves nothing.
	if matched < n/10 || matched > n*9/10 {
		t.Fatalf("%d of %d generated names match: the generator no longer covers both sides", matched, n)
	}
}

func FuzzNamePatternAgreesWithTheTransform(f *testing.F) {
	for _, s := range []string{"alice", "alice.smith", "-a", "A", strings.Repeat("a", 64), "", "K"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := nameRE.MatchString(s), unchanged(s); got != want {
			t.Fatalf("pattern on %q = %v, transform leaves it unchanged = %v", s, got, want)
		}
	})
}

// The CRDs controller-gen generates, and the authn-crds chart ships, carry
// exactly this rule, at the root, checked at create only.
func TestCRDsCarryTheNameRule(t *testing.T) {
	for _, dir := range []string{
		filepath.Join("..", "crds"),
		filepath.Join("..", "..", "..", "helm", "authn-crds", "templates"),
	} {
		for _, file := range []string{
			"basic.authn.krateo.io_users.yaml",
			"serviceaccount.authn.krateo.io_serviceaccounts.yaml",
		} {
			path := filepath.Join(dir, file)
			rules := rootRules(t, path)
			if len(rules) != 1 {
				t.Errorf("%s: %d root x-kubernetes-validations, want 1: %+v", path, len(rules), rules)
				continue
			}
			r := rules[0]
			if r.Rule != nameRule {
				t.Errorf("%s: rule %q, want %q", path, r.Rule, nameRule)
			}
			if r.Message != nameMessage {
				t.Errorf("%s: message %q, want %q", path, r.Message, nameMessage)
			}
			if r.OptionalOldSelf == nil || !*r.OptionalOldSelf {
				t.Errorf("%s: optionalOldSelf is not true, so the rule would not run at create", path)
			}
		}
	}
}

type validationRule struct {
	Rule            string `json:"rule"`
	Message         string `json:"message"`
	OptionalOldSelf *bool  `json:"optionalOldSelf"`
}

func rootRules(t *testing.T, path string) []validationRule {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	js, err := yaml.ToJSON(raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						XValidations []validationRule `json:"x-kubernetes-validations"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(js, &crd); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if len(crd.Spec.Versions) != 1 {
		t.Fatalf("%s: %d versions, want 1", path, len(crd.Spec.Versions))
	}
	return crd.Spec.Versions[0].Schema.OpenAPIV3Schema.XValidations
}
