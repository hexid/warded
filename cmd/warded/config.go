package main

import (
	"encoding/json"

	"github.com/hexid/warded"
)

type wardedConfig struct {
	Ward  warded.WardConfig            `json:"ward"`
	Wards map[string]warded.WardConfig `json:"wards"`
}

func (c wardedConfig) Get(name string) warded.WardConfig {
	config := c.Ward
	if wardConf, ok := c.Wards[name]; ok {
		config = wardConf
	}
	return config
}

func (c *wardedConfig) UnmarshalJSON(data []byte) error {
	config := struct {
		Ward  warded.WardConfig           `json:"ward"`
		Wards map[string]*json.RawMessage `json:"wards"`
	}{
		Ward: warded.DefaultWardConfig(),
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	c.Ward = config.Ward
	if c.Wards == nil {
		c.Wards = make(map[string]warded.WardConfig)
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
