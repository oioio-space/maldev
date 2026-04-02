package transport

import (
	"time"
)

// Config contains common transport configuration.
type Config struct {
	Address        string
	Timeout        time.Duration
	UseTLS         bool
	TLSCertPath    string
	TLSKeyPath     string
	TLSInsecure    bool
	TLSFingerprint string
}

// New creates the appropriate transport based on configuration.
func New(cfg *Config) (Transport, error) {
	if cfg.UseTLS {
		var opts []TLSOption
		if cfg.TLSInsecure {
			opts = append(opts, WithInsecure(true))
		}
		if cfg.TLSFingerprint != "" {
			opts = append(opts, WithFingerprint(cfg.TLSFingerprint))
		}

		return NewTLS(
			cfg.Address,
			cfg.Timeout,
			cfg.TLSCertPath,
			cfg.TLSKeyPath,
			opts...,
		), nil
	}

	return NewTCP(cfg.Address, cfg.Timeout), nil
}
