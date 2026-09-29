package clienturi

import (
	"fmt"
	"net"
	"net/url"

	"gopkg.in/yaml.v3"
)

type serverOptions struct {
	Obfs struct {
		Type       string `yaml:"type"`
		Salamander struct {
			Password string `yaml:"password"`
		} `yaml:"salamander"`
		Gecko struct {
			Password string `yaml:"password"`
		} `yaml:"gecko"`
	} `yaml:"obfs"`
}

// Build creates a standard Hysteria 2 share URI. Port 443 is kept explicit for
// compatibility with clients that do not apply the scheme's default port.
func Build(domain, username, password string, config []byte) (string, error) {
	var options serverOptions
	if err := yaml.Unmarshal(config, &options); err != nil {
		return "", fmt.Errorf("parse client options: %w", err)
	}
	u := &url.URL{
		Scheme:   "hysteria2",
		Host:     net.JoinHostPort(domain, "443"),
		Path:     "/",
		User:     url.UserPassword(username, password),
		Fragment: username,
	}
	query := make(url.Values)
	switch options.Obfs.Type {
	case "":
	case "salamander":
		query.Set("obfs", "salamander")
		query.Set("obfs-password", options.Obfs.Salamander.Password)
	case "gecko":
		query.Set("obfs", "gecko")
		query.Set("obfs-password", options.Obfs.Gecko.Password)
	default:
		return "", fmt.Errorf("unsupported obfs type %q", options.Obfs.Type)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}
