package scanner

import (
	"fmt"
	"time"

	"github.com/sca-proxy/sca-proxy/internal/config"
	"github.com/sca-proxy/sca-proxy/internal/proxy"
)

// New builds an AV scanner from its config. Unknown types are an error.
func New(cfg config.ScannerConfig) (proxy.AVScanner, error) {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	switch cfg.Type {
	case "clamav":
		return NewClamAVScanner(cfg.Address, timeout)
	case "icap":
		return NewICAPScanner(cfg.Address, cfg.Service, timeout)
	default:
		return nil, fmt.Errorf("unknown malware scanner type %q", cfg.Type)
	}
}
