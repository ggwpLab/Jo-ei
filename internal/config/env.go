package config

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

// envPrefix prefixes every environment variable that sets a configuration key.
const envPrefix = "JOEI_"

// directEnv lists JOEI_* variables the code reads itself rather than through
// a configuration key.
var directEnv = map[string]bool{
	"JOEI_CONSOLE_JWT_SECRET": true,
}

// kubernetesServiceLinkRe matches the service-link variables Kubernetes
// injects for every Service in the namespace — <SVC>_SERVICE_HOST,
// <SVC>_SERVICE_PORT[_<NAME>], <SVC>_PORT and <SVC>_PORT_<n>_<PROTO>[_ADDR|
// _PORT|_PROTO] — for Services named "joei" or "joei-…" (joei-metrics, a
// release "joei" of chart "jo-ei", subcharts). They are not configuration.
// Checked only after the schema, so a real key is never mistaken for one.
var kubernetesServiceLinkRe = regexp.MustCompile(`^JOEI_(?:[A-Z0-9_]+_)?(?:SERVICE_HOST|SERVICE_PORT(?:_[A-Z0-9_]+)?|PORT(?:_[0-9]+_(?:TCP|UDP|SCTP)(?:_(?:ADDR|PORT|PROTO))?)?)$`)

// envSchema is the set of configuration keys an environment variable can set,
// derived from the Config struct so it never drifts from it.
type envSchema struct {
	// keys maps an environment variable name to the key it sets, for every
	// scalar and string-list key.
	keys map[string]string
	// fileOnly maps the variable-name prefix of every list-of-objects or map
	// key (malware.scanners, policy.profiles) to that key: a single variable
	// cannot express them.
	fileOnly map[string]string
}

func envName(key string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// buildEnvSchema walks Config by its mapstructure tags.
func buildEnvSchema() envSchema {
	s := envSchema{keys: map[string]string{}, fileOnly: map[string]string{}}
	s.walk(reflect.TypeFor[Config](), "")
	return s
}

func (s envSchema) walk(t reflect.Type, prefix string) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("mapstructure"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch {
		case ft.Kind() == reflect.Struct:
			s.walk(ft, key)
		case ft.Kind() == reflect.Map,
			ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct:
			s.fileOnly[envName(key)] = key
		default:
			s.keys[envName(key)] = key
		}
	}
}

// bind binds every settable key to its variable, so a variable works whether
// or not the file mentions the key (viper's AutomaticEnv alone only overrides
// keys it already knows).
func (s envSchema) bind(v *viper.Viper) error {
	for name, key := range s.keys {
		if err := v.BindEnv(key, name); err != nil {
			return fmt.Errorf("binding %s: %w", name, err)
		}
	}
	return nil
}

// unknown lists the non-empty JOEI_* variables in environ that set nothing:
// not a schema key, not a key the loaded file defines (fileKeys, so a field of
// a defined policy profile can still be overridden), not read directly by the
// code, not a Kubernetes service link. An empty value sets nothing either, but
// viper ignores it too, so it is not reported — compose .env templates leave
// variables empty.
func (s envSchema) unknown(fileKeys []string, environ []string) []string {
	inFile := make(map[string]bool, len(fileKeys))
	for _, k := range fileKeys {
		inFile[envName(k)] = true
	}
	var problems []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, envPrefix) || value == "" {
			continue
		}
		if _, ok := s.keys[name]; ok || inFile[name] || directEnv[name] || kubernetesServiceLinkRe.MatchString(name) {
			continue
		}
		if key, ok := fileOnlyKey(s, name); ok {
			problems = append(problems, fmt.Sprintf("%s: %s is a list of objects or a map; set it in the config file", name, key))
			continue
		}
		problems = append(problems, fmt.Sprintf("%s: no such setting", name))
	}
	sort.Strings(problems)
	return problems
}

// fileOnlyKey reports the list/map key a variable name falls under.
func fileOnlyKey(s envSchema, name string) (string, bool) {
	for prefix, key := range s.fileOnly {
		if name == prefix || strings.HasPrefix(name, prefix+"_") {
			return key, true
		}
	}
	return "", false
}

// environ is os.Environ, replaceable in tests of this package.
var environ = os.Environ
