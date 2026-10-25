package config

import (
	"errors"
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

// kubernetesServiceLinkRe matches the variables Kubernetes injects for a
// Service named "joei" (JOEI_SERVICE_HOST, JOEI_PORT_8080_TCP_ADDR, ...).
// They are not configuration and must not stop the pod from starting.
var kubernetesServiceLinkRe = regexp.MustCompile(`^JOEI_(SERVICE_HOST|SERVICE_PORT(_.+)?|PORT(_.+)?)$`)

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

// bindEnv binds every settable key to its variable, so a variable works
// whether or not the file mentions the key (viper's AutomaticEnv alone only
// overrides keys it already knows), and rejects JOEI_* variables that set
// nothing: a misspelt name, or one aimed at a list of objects or a map, would
// otherwise be ignored without a word.
func bindEnv(v *viper.Viper, environ []string) error {
	s := buildEnvSchema()
	for name, key := range s.keys {
		if err := v.BindEnv(key, name); err != nil {
			return fmt.Errorf("binding %s: %w", name, err)
		}
	}

	var problems []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, envPrefix) {
			continue
		}
		if _, ok := s.keys[name]; ok || directEnv[name] || kubernetesServiceLinkRe.MatchString(name) {
			continue
		}
		if key, ok := fileOnlyKey(s, name); ok {
			problems = append(problems, fmt.Sprintf("%s: %s is a list of objects or a map and can only be set in the config file", name, key))
			continue
		}
		problems = append(problems, fmt.Sprintf("%s: no such setting", name))
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return errors.New("environment: " + strings.Join(problems, "; "))
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
