package warded

import (
	"encoding/json"
)

// WardConfig contains the configuration for the ward
type WardConfig struct {
	KeyDerivation KeyDerivationConfig `json:"keyDerivation"`
	Cipher        string              `json:"cipher"`
}

// DefaultWardConfig returns the default WardConfig.
// This contains recommended values.
func DefaultWardConfig() WardConfig {
	return WardConfig{
		Cipher: "chacha20poly1305",
		KeyDerivation: KeyDerivationConfig{
			Type: TypeScrypt,
			Data: &Scrypt{
				Iterations: 16384, // 2**14
				BlockSize:  8,
				Parallel:   1,
			},
		},
	}
}

// Config contains the general and ward-specific configurations.
// Ward is the general configuration and defaults
// to the default ward configuration.
// Wards is a map from ward name to configuration
// and defaults to the general ward configuration.
type Config struct {
	Ward  WardConfig            `json:"ward"`
	Wards map[string]WardConfig `json:"wards"`
}

// GetWardConfig returns the ward-specific configuration,
// if one exists. Otherwise, the general config is returned.
func (c Config) GetWardConfig(name string) WardConfig {
	config := c.Ward
	if wardConf, ok := c.Wards[name]; ok {
		config = wardConf
	}
	return config
}

// UnmarshalJSON unmarshals the warded configuration.
func (c *Config) UnmarshalJSON(data []byte) error {
	config := struct {
		Ward  WardConfig                  `json:"ward"`
		Wards map[string]*json.RawMessage `json:"wards"`
	}{
		Ward: DefaultWardConfig(),
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	c.Ward = config.Ward
	if c.Wards == nil {
		c.Wards = make(map[string]WardConfig)
	}

	for name, raw := range config.Wards {
		base := config.Ward
		if err := json.Unmarshal(*raw, &base); err != nil {
			return err
		}
		c.Wards[name] = base
	}

	return nil
}
