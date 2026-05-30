package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Registries  RegistriesConfig  `mapstructure:"registries"`
	SupplyChain SupplyChainConfig `mapstructure:"supply_chain"`
	Cache       CacheConfig       `mapstructure:"cache"`
	Policy      PolicyConfig      `mapstructure:"policy"`
	Logging     LoggingConfig     `mapstructure:"logging"`
}

type ServerConfig struct {
	Listen string    `mapstructure:"listen"`
	TLS    TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type RegistriesConfig struct {
	PyPI  RegistryConfig `mapstructure:"pypi"`
	NPM   RegistryConfig `mapstructure:"npm"`
	Maven RegistryConfig `mapstructure:"maven"`
}

type RegistryConfig struct {
	Upstream string `mapstructure:"upstream"`
	Enabled  bool   `mapstructure:"enabled"`
}

type SupplyChainConfig struct {
	MinAgeHours   int    `mapstructure:"min_age_hours"`
	AllowlistPath string `mapstructure:"allowlist_path"`
	Mode          string `mapstructure:"mode"` // enforce | dry_run | off
}

type CacheConfig struct {
	Backend string     `mapstructure:"backend"` // local | s3
	Local   LocalCache `mapstructure:"local"`
	S3      S3Cache    `mapstructure:"s3"`
}

type LocalCache struct {
	Path      string `mapstructure:"path"`
	MaxSizeGB int    `mapstructure:"max_size_gb"`
}

type S3Cache struct {
	Endpoint string `mapstructure:"endpoint"`
	Bucket   string `mapstructure:"bucket"`
	Region   string `mapstructure:"region"`
}

type PolicyConfig struct {
	ActiveProfile string                   `mapstructure:"active_profile"`
	Profiles      map[string]PolicyProfile `mapstructure:"profiles"`
}

type PolicyProfile struct {
	CVEBlock         bool `mapstructure:"cve_block"`
	SupplyChainBlock bool `mapstructure:"supply_chain_block"`
	MalwareBlock     bool `mapstructure:"malware_block"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// Load reads a YAML config file and returns a Config.
// Environment variables prefixed with SCAPROXY_ override file values.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("SCAPROXY")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	return &cfg, nil
}
