package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type FilterConfig struct {
	Address []string `json:"address"`
	Port    []string `json:"port"`
}

type Config struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	DeviceName string `json:"device_name"`
	// InterfaceName string       `json:"interface_name"`
	// "interface_name": "Ethernet",
	PcapName   string       `json:"pcap_name"`
	Snaplen    int          `json:"snaplen"`
	IsLoopBack bool         `json:"is_loop_back"`
	Filter     FilterConfig `json:"filter"`
}

func ReadConfigFile(filename string) *Config {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	var conf Config
	err = json.Unmarshal(data, &conf)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return &conf
}
