package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/auth"
	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/settings"
)

// jwtSecretSettingKey stores the generated signing key in the settings table,
// so a restart does not log every operator out.
//
//nolint:gosec // G101: this is a settings-store key name, not a credential value.
const jwtSecretSettingKey = "auth.jwt_secret"

// resolveJWTSecret returns the console's token-signing key, in order of
// precedence: JOEI_CONSOLE_JWT_SECRET, the config file, the settings store, or
// a freshly generated key which is then persisted.
//
// The environment is read directly rather than through viper, exactly as
// JOEI_CONSOLE_AUTH_USERS is: viper's AutomaticEnv only overrides keys that are
// present in the config file, so an env-only secret would silently not apply.
func resolveJWTSecret(fileValue string, st *settings.Store, logger zerolog.Logger) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("JOEI_CONSOLE_JWT_SECRET")); v != "" {
		return []byte(v), nil
	}
	if v := strings.TrimSpace(fileValue); v != "" {
		return []byte(v), nil
	}
	raw, ok, err := st.Get(jwtSecretSettingKey)
	if err != nil {
		return nil, fmt.Errorf("reading the stored console signing key: %w", err)
	}
	if ok {
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, fmt.Errorf("decoding the stored console signing key: %w", err)
		}
		secret, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decoding the stored console signing key: %w", err)
		}
		if len(secret) >= auth.MinSecretLen {
			return secret, nil
		}
		logger.Warn().Msg("console auth: the stored signing key is too short; generating a new one (existing sessions end)")
	}
	secret := make([]byte, auth.MinSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating a console signing key: %w", err)
	}
	value, err := json.Marshal(base64.StdEncoding.EncodeToString(secret))
	if err != nil {
		return nil, fmt.Errorf("encoding the console signing key: %w", err)
	}
	if err := st.Put(jwtSecretSettingKey, value); err != nil {
		return nil, fmt.Errorf("storing the console signing key: %w", err)
	}
	logger.Info().Msg("console auth: generated a session signing key and stored it in the database (set console.auth.jwt_secret or JOEI_CONSOLE_JWT_SECRET to share one across replicas)")
	return secret, nil
}

// authTTLs resolves the configured session lifetimes, applying the defaults for
// unset keys.
func authTTLs(c config.AuthConfig) (access, refresh time.Duration) {
	minutes := c.AccessTTLMinutes
	if minutes <= 0 {
		minutes = config.DefaultAccessTTLMinutes
	}
	hours := c.RefreshTTLHours
	if hours <= 0 {
		hours = config.DefaultRefreshTTLHours
	}
	return time.Duration(minutes) * time.Minute, time.Duration(hours) * time.Hour
}
