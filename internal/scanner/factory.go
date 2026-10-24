// Package scanner implements CVE and malware scanners.
package scanner

import (
	"fmt"
	"time"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
)

// New builds an AV scanner from its config. Unknown types are an error. The
// scanner reports cfg.DisplayName() as the engine of its verdicts.
func New(cfg config.ScannerConfig) (gate.AVScanner, error) {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	switch cfg.Type {
	case "clamav":
		s, err := NewClamAVScanner(cfg.Address, timeout)
		if err != nil {
			return nil, err
		}
		s.name = cfg.DisplayName()
		return s, nil
	case "icap":
		s, err := NewICAPScanner(cfg.Address, cfg.Service, timeout)
		if err != nil {
			return nil, err
		}
		s.name = cfg.DisplayName()
		return s, nil
	default:
		return nil, fmt.Errorf("unknown malware scanner type %q", cfg.Type)
	}
}
