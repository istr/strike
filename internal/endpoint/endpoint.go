package endpoint

import "encoding/json"

// Addr returns the endpoint's network address.
func (e TLS) Addr() Address { return e.Host }

// Addr returns the endpoint's network address.
func (e SSH) Addr() Address { return e.Host }

// MarshalJSON projects the host to its packed authority wire form.
func (e TLS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Trust Trust  `json:"trust"`
		Type  string `json:"type"`
		Host  string `json:"host"`
	}{Type: e.Type, Host: e.Host.Authority(), Trust: e.Trust})
}

// MarshalJSON projects the host to its packed authority wire form.
func (e SSH) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type       string    `json:"type"`
		Host       string    `json:"host"`
		KnownHosts []HostKey `json:"knownHosts"`
	}{Type: e.Type, Host: e.Host.Authority(), KnownHosts: e.KnownHosts})
}
