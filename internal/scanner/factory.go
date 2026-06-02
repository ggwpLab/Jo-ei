// Package scanner implements CVE and malware scanners.
package scanner

import (
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
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
