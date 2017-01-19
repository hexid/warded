package warded

// WardConfig contains the configuration for the ward
type WardConfig struct {
	Scrypt Scrypt `json:"scrypt"`
}

// DefaultWardConfig returns the default WardConfig.
// This contains recommended values.
func DefaultWardConfig() WardConfig {
	return WardConfig{
		Scrypt: Scrypt{
			Iterations: 16384, // 2**14
			BlockSize:  8,
			Parallel:   1,
		},
	}
}
