package serverconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	configFilename       = "hysteria.yaml"
	legacyConfigFilename = "config.yaml"
)

type Managed struct {
	Listen   string
	CertFile string
	KeyFile  string
	DecoyURL string
}

type User struct {
	Name     string
	Password string
}

type AccessRules struct {
	Rules        []AccessRule
	OtherCount   int
	SniffEnabled bool
}

type AccessRule struct {
	Action string
	Domain string
}

type Store struct {
	mu      sync.Mutex
	path    string
	managed Managed
}

func NewStore(dataDir string, managed Managed) *Store {
	return &Store{path: filepath.Join(dataDir, configFilename), managed: managed}
}

func (s *Store) Path() string { return s.path }

func (s *Store) Ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	legacyPath := filepath.Join(filepath.Dir(s.path), legacyConfigFilename)
	if _, err := os.Lstat(legacyPath); err == nil {
		if _, currentErr := os.Lstat(s.path); currentErr == nil {
			return fmt.Errorf("migration conflict: both %s and %s exist; resolve manually before starting", legacyPath, s.path)
		} else if !errors.Is(currentErr, fs.ErrNotExist) {
			return fmt.Errorf("stat config during migration check: %w", currentErr)
		}
		return fmt.Errorf("migration required: %s exists; copy it to %s with the rest of runtime state before starting", legacyPath, s.path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat legacy config: %w", err)
	}
	if _, err := os.Lstat(s.path); err == nil {
		raw, err := os.ReadFile(s.path)
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}
		doc, err := s.validateManaged(raw, false)
		if err != nil {
			return err
		}
		proxy := mappingValue(mappingValue(doc.Content[0], "masquerade"), "proxy")
		decoyURL := mappingValue(proxy, "url")
		if decoyURL.Value == s.managed.DecoyURL {
			return nil
		}
		decoyURL.Value = s.managed.DecoyURL
		var out bytes.Buffer
		enc := yaml.NewEncoder(&out)
		enc.SetIndent(2)
		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("encode config with HWUI_DECOY_URL: %w", err)
		}
		if err := enc.Close(); err != nil {
			return fmt.Errorf("close config encoder: %w", err)
		}
		if _, err := s.validate(out.Bytes()); err != nil {
			return fmt.Errorf("validate config with HWUI_DECOY_URL: %w", err)
		}
		if err := atomicWrite(s.path, out.Bytes(), 0o600); err != nil {
			return fmt.Errorf("update masquerade URL from HWUI_DECOY_URL: %w", err)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat config: %w", err)
	}
	// Only these files prove that this directory contains an existing runtime.
	// Other files (including a test executable) are not evidence of migration.
	for _, name := range []string{
		"session.key", "certs/fullchain.pem", "certs/privatekey.pem",
		"acme/account.key", "acme/registration.json",
	} {
		path := filepath.Join(filepath.Dir(s.path), name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("incomplete runtime: %s exists without %s; restore the full state before starting", path, s.path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat runtime state %s: %w", path, err)
		}
	}
	raw := []byte(fmt.Sprintf(`listen: %s
tls:
  cert: %s
  key: %s
auth:
  type: userpass
  userpass: {}
masquerade:
  type: proxy
  proxy:
    url: %s
    rewriteHost: true
`, s.managed.Listen, s.managed.CertFile, s.managed.KeyFile, s.managed.DecoyURL))
	if _, err := s.validate(raw); err != nil {
		return fmt.Errorf("validate generated config: %w", err)
	}
	return atomicWrite(s.path, raw, 0o600)
}

func (s *Store) Read() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readValidatedLocked()
}

func (s *Store) Validate(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.validate(raw)
	return err
}

func (s *Store) Users() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := s.readValidatedLocked()
	if err != nil {
		return nil, err
	}
	doc, err := s.validate(raw)
	if err != nil {
		return nil, err
	}
	userpass := mappingValue(mappingValue(doc.Content[0], "auth"), "userpass")
	users := make([]User, 0, len(userpass.Content)/2)
	for i := 0; i < len(userpass.Content); i += 2 {
		users = append(users, User{Name: userpass.Content[i].Value, Password: userpass.Content[i+1].Value})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users, nil
}

func (s *Store) User(name string) (User, error) {
	users, err := s.Users()
	if err != nil {
		return User{}, err
	}
	for _, user := range users {
		if user.Name == name {
			return user, nil
		}
	}
	return User{}, fmt.Errorf("user %q does not exist", name)
}

func (s *Store) AddUser(name, password string, apply func() error) error {
	return s.mutateUsers(apply, func(users *yaml.Node) error {
		if err := validateCredential(name, password); err != nil {
			return err
		}
		if mappingValue(users, name) != nil {
			return fmt.Errorf("user %q already exists", name)
		}
		users.Content = append(users.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: password},
		)
		return nil
	})
}

func (s *Store) DeleteUser(name string, apply func() error) error {
	return s.mutateUsers(apply, func(users *yaml.Node) error {
		for i := 0; i < len(users.Content); i += 2 {
			if users.Content[i].Value == name {
				users.Content = append(users.Content[:i], users.Content[i+2:]...)
				return nil
			}
		}
		return fmt.Errorf("user %q does not exist", name)
	})
}

func (s *Store) Save(raw []byte, apply func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validate(raw); err != nil {
		return err
	}
	return s.commitLocked(raw, apply)
}

func (s *Store) AccessRules() (AccessRules, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := s.readValidatedLocked()
	if err != nil {
		return AccessRules{}, err
	}
	doc, err := s.validate(raw)
	if err != nil {
		return AccessRules{}, err
	}
	root := doc.Content[0]
	rules := AccessRules{SniffEnabled: scalarBool(mappingValue(mappingValue(root, "sniff"), "enable"))}
	acl := mappingValue(root, "acl")
	if acl == nil {
		return rules, nil
	}
	if acl.Kind != yaml.MappingNode {
		return AccessRules{}, errors.New("acl must be a mapping")
	}
	if err := rejectDuplicateKeys(acl, "acl"); err != nil {
		return AccessRules{}, err
	}
	if mappingValue(acl, "file") != nil {
		return AccessRules{}, errors.New("ACL uses acl.file; switch to acl.inline in the YAML editor before using lists")
	}
	inline := mappingValue(acl, "inline")
	if inline == nil {
		return rules, nil
	}
	if inline.Kind != yaml.SequenceNode {
		return AccessRules{}, errors.New("acl.inline must be a list")
	}
	for _, item := range inline.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return AccessRules{}, lineError(item, "acl.inline entries must be strings")
		}
		if suffix, ok := suffixRule(item.Value, "direct"); ok {
			rules.Rules = append(rules.Rules, AccessRule{Action: "allow", Domain: suffix})
		} else if suffix, ok := suffixRule(item.Value, "reject"); ok {
			rules.Rules = append(rules.Rules, AccessRule{Action: "block", Domain: suffix})
		} else {
			rules.OtherCount++
		}
	}
	return rules, nil
}

func (s *Store) SetAccessRules(rules []AccessRule, apply func() error) error {
	normalized, err := normalizeAccessRules(rules)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := s.readValidatedLocked()
	if err != nil {
		return err
	}
	doc, err := s.validate(raw)
	if err != nil {
		return err
	}
	root := doc.Content[0]
	acl := mappingValue(root, "acl")
	if acl == nil {
		acl = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, scalarNode("acl"), acl)
	} else if acl.Kind != yaml.MappingNode {
		return errors.New("acl must be a mapping")
	}
	if err := rejectDuplicateKeys(acl, "acl"); err != nil {
		return err
	}
	if mappingValue(acl, "file") != nil {
		return errors.New("ACL uses acl.file; switch to acl.inline in the YAML editor before using lists")
	}
	inline := mappingValue(acl, "inline")
	if inline == nil {
		inline = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		acl.Content = append(acl.Content, scalarNode("inline"), inline)
	} else if inline.Kind != yaml.SequenceNode {
		return errors.New("acl.inline must be a list")
	}
	other := make([]*yaml.Node, 0, len(inline.Content))
	for _, item := range inline.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return lineError(item, "acl.inline entries must be strings")
		}
		if _, ok := suffixRule(item.Value, "direct"); ok {
			continue
		}
		if _, ok := suffixRule(item.Value, "reject"); ok {
			continue
		}
		other = append(other, item)
	}
	inline.Content = inline.Content[:0]
	for _, rule := range normalized {
		outbound := "direct"
		if rule.Action == "block" {
			outbound = "reject"
		}
		inline.Content = append(inline.Content, scalarNode(outbound+"(suffix:"+rule.Domain+")"))
	}
	inline.Content = append(inline.Content, other...)
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close config encoder: %w", err)
	}
	if _, err := s.validate(out.Bytes()); err != nil {
		return fmt.Errorf("validate updated config: %w", err)
	}
	return s.commitLocked(out.Bytes(), apply)
}

func (s *Store) mutateUsers(apply func() error, mutate func(*yaml.Node) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := s.readValidatedLocked()
	if err != nil {
		return err
	}
	doc, err := s.validate(raw)
	if err != nil {
		return err
	}
	users := mappingValue(mappingValue(doc.Content[0], "auth"), "userpass")
	if err := mutate(users); err != nil {
		return err
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close config encoder: %w", err)
	}
	if _, err := s.validate(out.Bytes()); err != nil {
		return fmt.Errorf("validate updated config: %w", err)
	}
	return s.commitLocked(out.Bytes(), apply)
}

func (s *Store) commitLocked(raw []byte, apply func() error) error {
	previous, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read previous config: %w", err)
	}
	if err := atomicWrite(s.path, raw, 0o600); err != nil {
		return err
	}
	if apply == nil {
		return nil
	}
	if err := apply(); err == nil {
		return nil
	} else {
		applyErr := err
		if rollbackErr := atomicWrite(s.path, previous, 0o600); rollbackErr != nil {
			return fmt.Errorf("apply config: %v; restore previous config: %w", applyErr, rollbackErr)
		}
		if rollbackErr := apply(); rollbackErr != nil {
			return fmt.Errorf("apply config: %v; restart previous config: %w", applyErr, rollbackErr)
		}
		return fmt.Errorf("apply config: %w; previous config restored", applyErr)
	}
}

func (s *Store) readValidatedLocked() ([]byte, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if _, err := s.validate(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *Store) validate(raw []byte) (*yaml.Node, error) {
	return s.validateManaged(raw, true)
}

func (s *Store) validateManaged(raw []byte, enforceDecoyURL bool) (*yaml.Node, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("config is empty")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(false)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("YAML syntax: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config root must be a mapping")
	}
	root := doc.Content[0]
	if err := rejectDuplicateKeys(root, "config"); err != nil {
		return nil, err
	}
	if mappingValue(root, "acme") != nil {
		return nil, errors.New("config.acme is managed by the panel and must be absent")
	}
	if err := requireScalar(root, "listen", s.managed.Listen); err != nil {
		return nil, err
	}
	tls, err := requireMap(root, "tls")
	if err != nil {
		return nil, err
	}
	if err := requireScalar(tls, "cert", s.managed.CertFile); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if err := requireScalar(tls, "key", s.managed.KeyFile); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	auth, err := requireMap(root, "auth")
	if err != nil {
		return nil, err
	}
	if err := requireScalar(auth, "type", "userpass"); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	users, err := requireMap(auth, "userpass")
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	if err := rejectDuplicateKeys(users, "auth.userpass"); err != nil {
		return nil, err
	}
	for i := 0; i < len(users.Content); i += 2 {
		key, value := users.Content[i], users.Content[i+1]
		if key.Kind != yaml.ScalarNode || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return nil, lineError(key, "auth.userpass entries must be string pairs")
		}
		if err := validateCredential(key.Value, value.Value); err != nil {
			return nil, lineError(key, err.Error())
		}
	}
	masquerade, err := requireMap(root, "masquerade")
	if err != nil {
		return nil, err
	}
	if err := requireScalar(masquerade, "type", "proxy"); err != nil {
		return nil, fmt.Errorf("masquerade: %w", err)
	}
	proxy, err := requireMap(masquerade, "proxy")
	if err != nil {
		return nil, fmt.Errorf("masquerade: %w", err)
	}
	decoyURL := mappingValue(proxy, "url")
	if decoyURL == nil || decoyURL.Kind != yaml.ScalarNode || decoyURL.Tag != "!!str" {
		return nil, errors.New("masquerade.proxy.url must be a string")
	}
	if enforceDecoyURL && decoyURL.Value != s.managed.DecoyURL {
		return nil, fmt.Errorf("masquerade.proxy.url is managed by HWUI_DECOY_URL and must equal %q", s.managed.DecoyURL)
	}
	rewrite := mappingValue(proxy, "rewriteHost")
	if rewrite == nil || rewrite.Kind != yaml.ScalarNode || rewrite.Tag != "!!bool" || rewrite.Value != "true" {
		return nil, errors.New("masquerade.proxy.rewriteHost must be true")
	}
	return &doc, nil
}

func validateCredential(name, password string) error {
	if strings.TrimSpace(name) == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00:") {
		return errors.New("user name must be 1-128 characters and contain no colon or control line breaks")
	}
	if password == "" || len(password) > 512 || strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("password must be 1-512 characters and contain no control line breaks")
	}
	return nil
}

func normalizeAccessRules(rules []AccessRule) ([]AccessRule, error) {
	seen := make(map[string]struct{}, len(rules))
	result := make([]AccessRule, 0, len(rules))
	for i, rule := range rules {
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		if action != "allow" && action != "block" {
			return nil, fmt.Errorf("rule %d: action must be allow or block", i+1)
		}
		domain := strings.TrimSpace(rule.Domain)
		domain = strings.TrimPrefix(domain, "suffix:")
		domain = strings.TrimPrefix(domain, "*.")
		domain = strings.TrimPrefix(domain, ".")
		domain = strings.TrimSuffix(domain, ".")
		domain = strings.ToLower(domain)
		if err := validateDomainSuffix(domain); err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i+1, rule.Domain, err)
		}
		key := action + "\x00" + domain
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("rule %d duplicates %s %q", i+1, action, domain)
		}
		seen[key] = struct{}{}
		result = append(result, AccessRule{Action: action, Domain: domain})
	}
	return result, nil
}

func validateDomainSuffix(value string) error {
	if value == "" || len(value) > 253 {
		return errors.New("must be a DNS suffix up to 253 characters")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("contains an invalid DNS label")
		}
		for _, r := range label {
			if r != '-' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return errors.New("use domain names only, without scheme, path, port, or ACL syntax")
			}
		}
	}
	return nil
}

func suffixRule(rule, outbound string) (string, bool) {
	prefix := outbound + "(suffix:"
	if !strings.HasPrefix(rule, prefix) || !strings.HasSuffix(rule, ")") {
		return "", false
	}
	suffix := strings.TrimSuffix(strings.TrimPrefix(rule, prefix), ")")
	if validateDomainSuffix(suffix) != nil {
		return "", false
	}
	return suffix, true
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func scalarBool(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!bool" && node.Value == "true"
}

func requireMap(parent *yaml.Node, key string) (*yaml.Node, error) {
	n := mappingValue(parent, key)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s must be a mapping", key)
	}
	if err := rejectDuplicateKeys(n, key); err != nil {
		return nil, err
	}
	return n, nil
}

func requireScalar(parent *yaml.Node, key, expected string) error {
	n := mappingValue(parent, key)
	if n == nil || n.Kind != yaml.ScalarNode || n.Value != expected {
		return fmt.Errorf("%s must equal %q", key, expected)
	}
	return nil
}

func mappingValue(parent *yaml.Node, key string) *yaml.Node {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1]
		}
	}
	return nil
}

func rejectDuplicateKeys(node *yaml.Node, location string) error {
	seen := make(map[string]struct{}, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if _, ok := seen[key.Value]; ok {
			return lineError(key, fmt.Sprintf("duplicate key %q in %s", key.Value, location))
		}
		seen[key.Value] = struct{}{}
	}
	return nil
}

func lineError(node *yaml.Node, message string) error {
	return fmt.Errorf("line %d, column %d: %s", node.Line, node.Column, message)
}

func atomicWrite(filename string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(tmpName, filename); err != nil {
		return fmt.Errorf("publish config: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}
