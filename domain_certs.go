package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	cloudflareAPITokenEnv             = "GLIDER_CLOUDFLARE_API_TOKEN"
	acmeDNSPropagationTimeoutEnv      = "GLIDER_ACME_DNS_PROPAGATION_TIMEOUT"
	acmeDNSPropagationPollIntervalEnv = "GLIDER_ACME_DNS_POLL_INTERVAL"
	cloudflareAPIBase                 = "https://api.cloudflare.com/client/v4"
	defaultACMEDirectoryURL           = acme.LetsEncryptURL
	defaultCertCacheDir               = "/etc/glider-certs"
	defaultACMEDNSPropagationTimeout  = 2 * time.Minute
	defaultACMEDNSPropagationPoll     = 5 * time.Second
	certsSnapshotFileName             = "certs_snapshot.json"
)

var cloudflareAPIBaseURL = cloudflareAPIBase

type CertificateSnapshot struct {
	CertVersion string       `json:"cert_version"`
	Domains     []DomainCert `json:"domains"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type DomainCert struct {
	Domain        string     `json:"domain"`
	FullchainPEM  string     `json:"fullchain_pem"`
	PrivateKeyPEM string     `json:"private_key_pem"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

type cloudflareClient struct {
	token   string
	baseURL string
	client  *http.Client
}

type cloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cloudflareDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type cloudflareResponse[T any] struct {
	Success bool                 `json:"success"`
	Errors  []cloudflareAPIError `json:"errors"`
	Result  T                    `json:"result"`
}

type cloudflareAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudflareTokenVerify struct {
	ID        string     `json:"id,omitempty"`
	Status    string     `json:"status,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	ExpiresOn *time.Time `json:"expires_on,omitempty"`
}

type cloudflareZoneCheck struct {
	Domain     string `json:"domain,omitempty"`
	ZoneID     string `json:"zone_id,omitempty"`
	ZoneName   string `json:"zone_name,omitempty"`
	ZoneReadOK bool   `json:"zone_read_ok"`
	DNSEditOK  bool   `json:"dns_edit_ok"`
	TestRecord string `json:"test_record,omitempty"`
}

type cloudflareDNSPlan struct {
	Domain          string `json:"domain,omitempty"`
	NodeID          string `json:"node_id,omitempty"`
	NodePublicIP    string `json:"node_public_ip,omitempty"`
	ZoneID          string `json:"zone_id,omitempty"`
	ZoneName        string `json:"zone_name,omitempty"`
	RecordID        string `json:"record_id,omitempty"`
	RecordName      string `json:"record_name,omitempty"`
	RecordType      string `json:"record_type,omitempty"`
	TargetContent   string `json:"target_content,omitempty"`
	TTL             int    `json:"ttl,omitempty"`
	Proxied         bool   `json:"proxied,omitempty"`
	ExistingID      string `json:"existing_id,omitempty"`
	ExistingContent string `json:"existing_content,omitempty"`
	ExistingTTL     int    `json:"existing_ttl,omitempty"`
	ExistingProxied bool   `json:"existing_proxied,omitempty"`
	Action          string `json:"action,omitempty"`
}

type dnsRecordDeleter interface {
	deleteRecord(ctx context.Context, zoneID, recordID string) error
}

func newCloudflareClient(token string) (*cloudflareClient, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("cloudflare API token is not configured")
	}
	return &cloudflareClient{
		token:   token,
		baseURL: cloudflareAPIBaseURL,
		client:  &http.Client{Timeout: 20 * time.Second},
	}, nil
}

func newCloudflareClientFromEnv() (*cloudflareClient, error) {
	cf, err := newCloudflareClient(os.Getenv(cloudflareAPITokenEnv))
	if err != nil {
		return nil, fmt.Errorf("%s is not set", cloudflareAPITokenEnv)
	}
	return cf, nil
}

func (c *cloudflareClient) findZone(ctx context.Context, domain string) (cloudflareZone, error) {
	name := domain
	for {
		var resp cloudflareResponse[[]cloudflareZone]
		query := url.Values{"name": []string{name}}
		if err := c.do(ctx, http.MethodGet, "/zones?"+query.Encode(), nil, &resp); err != nil {
			return cloudflareZone{}, err
		}
		if len(resp.Result) > 0 {
			return resp.Result[0], nil
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
	}
	return cloudflareZone{}, fmt.Errorf("cloudflare zone not found for %s", domain)
}

func (c *cloudflareClient) upsertRecord(ctx context.Context, zoneID string, rec cloudflareDNSRecord) (cloudflareDNSRecord, error) {
	if rec.Type == "" {
		rec.Type = "A"
	}
	if rec.TTL == 0 {
		rec.TTL = 1
	}
	if rec.ID == "" {
		existing, err := c.findRecord(ctx, zoneID, rec.Type, rec.Name)
		if err != nil {
			return cloudflareDNSRecord{}, err
		}
		if existing != nil {
			rec.ID = existing.ID
		}
	}
	payload := map[string]any{
		"type":    rec.Type,
		"name":    rec.Name,
		"content": rec.Content,
		"ttl":     rec.TTL,
		"proxied": rec.Proxied,
	}
	var resp cloudflareResponse[cloudflareDNSRecord]
	method := http.MethodPost
	path := "/zones/" + zoneID + "/dns_records"
	if rec.ID != "" {
		method = http.MethodPut
		path += "/" + rec.ID
	}
	if err := c.do(ctx, method, path, payload, &resp); err != nil {
		return cloudflareDNSRecord{}, err
	}
	return resp.Result, nil
}

func (c *cloudflareClient) findRecord(ctx context.Context, zoneID, recordType, name string) (*cloudflareDNSRecord, error) {
	var resp cloudflareResponse[[]cloudflareDNSRecord]
	query := url.Values{
		"type": []string{recordType},
		"name": []string{name},
	}
	path := "/zones/" + zoneID + "/dns_records?" + query.Encode()
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.Result) == 0 {
		return nil, nil
	}
	return &resp.Result[0], nil
}

func (c *cloudflareClient) createTXT(ctx context.Context, zoneID, name, value string) (string, error) {
	payload := map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     60,
		"proxied": false,
	}
	var resp cloudflareResponse[cloudflareDNSRecord]
	err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", payload, &resp)
	if err != nil {
		return "", err
	}
	return resp.Result.ID, nil
}

func (c *cloudflareClient) verifyToken(ctx context.Context, accountID string) (cloudflareTokenVerify, error) {
	path := "/user/tokens/verify"
	if strings.TrimSpace(accountID) != "" {
		path = "/accounts/" + url.PathEscape(strings.TrimSpace(accountID)) + "/tokens/verify"
	}
	var resp cloudflareResponse[cloudflareTokenVerify]
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return cloudflareTokenVerify{}, err
	}
	return resp.Result, nil
}

func (c *cloudflareClient) checkZone(ctx context.Context, domain string, dnsEditTest bool) (cloudflareZoneCheck, error) {
	normalized, err := normalizeDomainName(domain)
	if err != nil {
		return cloudflareZoneCheck{}, err
	}
	lookupDomain := strings.TrimPrefix(normalized, "*.")
	zone, err := c.findZone(ctx, lookupDomain)
	if err != nil {
		return cloudflareZoneCheck{Domain: normalized}, err
	}
	check := cloudflareZoneCheck{
		Domain:     normalized,
		ZoneID:     zone.ID,
		ZoneName:   zone.Name,
		ZoneReadOK: true,
	}
	if !dnsEditTest {
		return check, nil
	}
	suffix, err := randomHex(6)
	if err != nil {
		return check, err
	}
	recordName := "_glider-check-" + suffix + "." + zone.Name
	recordID, err := c.createTXT(ctx, zone.ID, recordName, "glider cloudflare permission check")
	if err != nil {
		return check, err
	}
	check.TestRecord = recordName
	if err := c.deleteRecord(context.Background(), zone.ID, recordID); err != nil {
		return check, fmt.Errorf("cloudflare DNS edit check cleanup failed for %s: %w", recordName, err)
	}
	check.DNSEditOK = true
	return check, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c *cloudflareClient) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	if recordID == "" {
		return nil
	}
	var resp cloudflareResponse[json.RawMessage]
	return c.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, &resp)
}

func (c *cloudflareClient) do(ctx context.Context, method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(payload); err != nil {
			return err
		}
		body = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare returned %s", resp.Status)
	}
	raw, _ := json.Marshal(out)
	var status struct {
		Success bool                 `json:"success"`
		Errors  []cloudflareAPIError `json:"errors"`
	}
	_ = json.Unmarshal(raw, &status)
	if !status.Success {
		return fmt.Errorf("cloudflare error: %s", cloudflareErrors(status.Errors))
	}
	return nil
}

func cloudflareErrors(errors []cloudflareAPIError) string {
	if len(errors) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(errors))
	for _, e := range errors {
		parts = append(parts, fmt.Sprintf("%d %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

func syncCloudflareDNS(ctx context.Context, d dbDomain, node NodeHeartbeat) (cloudflareDomainConfig, error) {
	return syncCloudflareDNSWithToken(ctx, d, node, os.Getenv(cloudflareAPITokenEnv))
}

func syncCloudflareDNSWithToken(ctx context.Context, d dbDomain, node NodeHeartbeat, token string) (cloudflareDomainConfig, error) {
	cf, err := newCloudflareClient(token)
	if err != nil {
		return cloudflareSyncFailed(d.Cloudflare, err), err
	}
	return syncCloudflareDNSWithClient(ctx, d, node, cf)
}

func syncCloudflareDNSWithClient(ctx context.Context, d dbDomain, node NodeHeartbeat, cf *cloudflareClient) (cloudflareDomainConfig, error) {
	plan, err := planCloudflareDNSWithClient(ctx, d, node, cf, false)
	if err != nil {
		return cloudflareSyncFailed(d.Cloudflare, err), err
	}
	rec, err := cf.upsertRecord(ctx, plan.ZoneID, cloudflareDNSRecord{
		ID:      plan.RecordID,
		Type:    plan.RecordType,
		Name:    plan.RecordName,
		Content: plan.TargetContent,
		TTL:     plan.TTL,
		Proxied: plan.Proxied,
	})
	out := d.Cloudflare
	if err != nil {
		return cloudflareSyncFailed(out, err), err
	}
	now := time.Now().UTC()
	out.ZoneID = plan.ZoneID
	out.ZoneName = plan.ZoneName
	out.RecordID = rec.ID
	out.RecordName = rec.Name
	out.RecordType = rec.Type
	out.TTL = rec.TTL
	out.Proxied = rec.Proxied
	out.LastSyncedAt = &now
	out.LastError = ""
	return out, nil
}

func planCloudflareDNSWithClient(ctx context.Context, d dbDomain, node NodeHeartbeat, cf *cloudflareClient, lookupExisting bool) (cloudflareDNSPlan, error) {
	if strings.TrimSpace(node.PublicIP) == "" {
		return cloudflareDNSPlan{}, fmt.Errorf("node %s has no public_ip", node.NodeID)
	}
	recType := strings.ToUpper(strings.TrimSpace(d.Cloudflare.RecordType))
	if recType == "" {
		if parsed := net.ParseIP(node.PublicIP); parsed != nil && parsed.To4() == nil {
			recType = "AAAA"
		} else {
			recType = "A"
		}
	}
	if recType != "A" && recType != "AAAA" {
		return cloudflareDNSPlan{}, fmt.Errorf("unsupported record type %s for node public_ip sync", recType)
	}
	publicIP := publicIPString(node.PublicIP)
	parsedIP := net.ParseIP(strings.TrimSpace(node.PublicIP))
	if parsedIP == nil {
		return cloudflareDNSPlan{}, fmt.Errorf("node %s public_ip is not an IP address", node.NodeID)
	}
	if publicIP == "" {
		return cloudflareDNSPlan{}, fmt.Errorf("node %s public_ip is not a public IP address", node.NodeID)
	}
	parsedIP = net.ParseIP(publicIP)
	if recType == "A" && parsedIP.To4() == nil {
		return cloudflareDNSPlan{}, fmt.Errorf("node %s public_ip is not IPv4", node.NodeID)
	}
	if recType == "AAAA" && parsedIP.To4() != nil {
		return cloudflareDNSPlan{}, fmt.Errorf("node %s public_ip is not IPv6", node.NodeID)
	}
	recordName := strings.TrimSpace(d.Cloudflare.RecordName)
	if recordName == "" {
		recordName = d.Domain
	}
	zoneID := strings.TrimSpace(d.Cloudflare.ZoneID)
	zoneName := strings.TrimSpace(d.Cloudflare.ZoneName)
	if zoneID == "" {
		zone, err := cf.findZone(ctx, d.Domain)
		if err != nil {
			return cloudflareDNSPlan{}, err
		}
		zoneID = zone.ID
		zoneName = zone.Name
	}
	ttl := d.Cloudflare.TTL
	if ttl == 0 {
		ttl = 1
	}
	plan := cloudflareDNSPlan{
		Domain:        d.Domain,
		NodeID:        node.NodeID,
		NodePublicIP:  publicIP,
		ZoneID:        zoneID,
		ZoneName:      zoneName,
		RecordID:      d.Cloudflare.RecordID,
		RecordName:    recordName,
		RecordType:    recType,
		TargetContent: publicIP,
		TTL:           ttl,
		Proxied:       d.Cloudflare.Proxied,
	}
	if lookupExisting {
		existing, err := cf.findRecord(ctx, zoneID, recType, recordName)
		if err != nil {
			return cloudflareDNSPlan{}, err
		}
		if existing != nil {
			plan.ExistingID = existing.ID
			plan.ExistingContent = existing.Content
			plan.ExistingTTL = existing.TTL
			plan.ExistingProxied = existing.Proxied
			if plan.RecordID == "" {
				plan.RecordID = existing.ID
			}
		}
	}
	plan.Action = plannedDNSAction(plan)
	return plan, nil
}

func plannedDNSAction(plan cloudflareDNSPlan) string {
	if plan.ExistingID != "" {
		if plan.ExistingContent == plan.TargetContent && plan.ExistingTTL == plan.TTL && plan.ExistingProxied == plan.Proxied {
			return "unchanged"
		}
		return "update"
	}
	if plan.RecordID != "" {
		return "update"
	}
	return "create"
}

func cloudflareSyncFailed(cf cloudflareDomainConfig, err error) cloudflareDomainConfig {
	if err != nil {
		cf.LastError = err.Error()
	}
	return cf
}

func issueCertificateWithCloudflare(ctx context.Context, d dbDomain, email, directoryURL string) (domainCertificate, error) {
	return issueCertificateWithCloudflareToken(ctx, d, email, directoryURL, os.Getenv(cloudflareAPITokenEnv))
}

func issueCertificateWithCloudflareToken(ctx context.Context, d dbDomain, email, directoryURL, token string) (domainCertificate, error) {
	return issueCertificateWithCloudflareTokenZone(ctx, d, email, directoryURL, token, "")
}

func issueCertificateWithCloudflareTokenZone(ctx context.Context, d dbDomain, email, directoryURL, token, zoneID string) (domainCertificate, error) {
	cf, err := newCloudflareClient(token)
	if err != nil {
		return d.Certificate, err
	}
	zoneID, err = resolveCertificateZoneID(ctx, d, cf, zoneID)
	if err != nil {
		return d.Certificate, err
	}

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return d.Certificate, err
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return d.Certificate, err
	}
	if directoryURL == "" {
		directoryURL = defaultACMEDirectoryURL
	}
	acmeClient := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
		UserAgent:    "glider-control-plane/" + version,
	}
	acct := &acme.Account{}
	if email != "" {
		acct.Contact = []string{"mailto:" + email}
	}
	if _, err := acmeClient.Register(ctx, acct, acme.AcceptTOS); err != nil {
		return d.Certificate, err
	}

	order, err := acmeClient.AuthorizeOrder(ctx, acme.DomainIDs(d.Domain))
	if err != nil {
		return d.Certificate, err
	}
	var txtRecordIDs []string
	defer func() {
		cleanupCloudflareRecords(context.Background(), cf, zoneID, txtRecordIDs)
	}()
	for _, authzURL := range order.AuthzURLs {
		authz, err := acmeClient.GetAuthorization(ctx, authzURL)
		if err != nil {
			return d.Certificate, err
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		chal := findDNS01Challenge(authz)
		if chal == nil {
			return d.Certificate, fmt.Errorf("dns-01 challenge not offered for %s", authz.Identifier.Value)
		}
		value, err := acmeClient.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return d.Certificate, err
		}
		recordName, err := dns01RecordName(authz.Identifier.Value)
		if err != nil {
			return d.Certificate, err
		}
		recordID, err := cf.createTXT(ctx, zoneID, recordName, value)
		if err != nil {
			return d.Certificate, err
		}
		txtRecordIDs = append(txtRecordIDs, recordID)
		if err := waitDNS01TXT(ctx, recordName, value); err != nil {
			return d.Certificate, err
		}
		if _, err := acmeClient.Accept(ctx, chal); err != nil {
			return d.Certificate, err
		}
		if _, err := acmeClient.WaitAuthorization(ctx, authz.URI); err != nil {
			return d.Certificate, err
		}
	}

	order, err = acmeClient.WaitOrder(ctx, order.URI)
	if err != nil {
		return d.Certificate, err
	}
	if order.Status != acme.StatusReady && order.Status != acme.StatusValid {
		return d.Certificate, fmt.Errorf("acme order status %s", order.Status)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: d.Domain},
		DNSNames: []string{d.Domain},
	}, certKey)
	if err != nil {
		return d.Certificate, err
	}
	derChain, _, err := acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return d.Certificate, err
	}
	fullchain, expiresAt, err := encodeCertChain(derChain)
	if err != nil {
		return d.Certificate, err
	}
	keyPEM, err := encodePrivateKey(certKey)
	if err != nil {
		return d.Certificate, err
	}
	now := time.Now().UTC()
	cert := domainCertificate{
		FullchainPEM:  fullchain,
		PrivateKeyPEM: keyPEM,
		IssuedAt:      &now,
		ExpiresAt:     expiresAt,
		LastIssuedAt:  &now,
		LastError:     "",
	}
	cert.Version = certificateVersion(DomainCert{
		Domain:        d.Domain,
		FullchainPEM:  cert.FullchainPEM,
		PrivateKeyPEM: cert.PrivateKeyPEM,
		ExpiresAt:     cert.ExpiresAt,
	})
	return cert, nil
}

func resolveCertificateZoneID(ctx context.Context, d dbDomain, cf *cloudflareClient, overrideZoneID string) (string, error) {
	if zoneID := strings.TrimSpace(overrideZoneID); zoneID != "" {
		return zoneID, nil
	}
	if zoneID := strings.TrimSpace(d.Cloudflare.ZoneID); zoneID != "" {
		return zoneID, nil
	}
	zone, err := cf.findZone(ctx, d.Domain)
	if err != nil {
		return "", err
	}
	return zone.ID, nil
}

func cleanupCloudflareRecords(ctx context.Context, deleter dnsRecordDeleter, zoneID string, recordIDs []string) {
	for _, recordID := range recordIDs {
		if strings.TrimSpace(recordID) == "" {
			continue
		}
		_ = deleter.deleteRecord(ctx, zoneID, recordID)
	}
}

func waitDNS01TXT(ctx context.Context, recordName, value string) error {
	timeout := envDuration(acmeDNSPropagationTimeoutEnv, defaultACMEDNSPropagationTimeout)
	if timeout <= 0 {
		return nil
	}
	interval := envDuration(acmeDNSPropagationPollIntervalEnv, defaultACMEDNSPropagationPoll)
	if interval <= 0 {
		interval = defaultACMEDNSPropagationPoll
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	resolver := net.DefaultResolver
	var lastErr error
	for {
		ok, err := lookupTXTValue(ctx, resolver, recordName, value)
		if ok {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("dns-01 TXT %s did not propagate before timeout: %w", recordName, lastErr)
			}
			return fmt.Errorf("dns-01 TXT %s did not propagate before timeout", recordName)
		case <-ticker.C:
		}
	}
}

type txtLookupResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

func lookupTXTValue(ctx context.Context, resolver txtLookupResolver, name, value string) (bool, error) {
	values, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return false, err
	}
	for _, txt := range values {
		if txt == value {
			return true, nil
		}
	}
	return false, nil
}

func dns01RecordName(domain string) (string, error) {
	domain, err := normalizeDomainName(domain)
	if err != nil {
		return "", err
	}
	return "_acme-challenge." + strings.TrimPrefix(domain, "*."), nil
}

func findDNS01Challenge(authz *acme.Authorization) *acme.Challenge {
	for _, c := range authz.Challenges {
		if c != nil && c.Type == "dns-01" {
			return c
		}
	}
	return nil
}

func encodeCertChain(derChain [][]byte) (string, *time.Time, error) {
	var buf bytes.Buffer
	var expiresAt *time.Time
	for i, der := range derChain {
		if i == 0 {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return "", nil, err
			}
			t := cert.NotAfter.UTC()
			expiresAt = &t
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return "", nil, err
		}
	}
	return buf.String(), expiresAt, nil
}

func encodePrivateKey(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func LoadCertificateSnapshotFromStore(ctx context.Context, store *mongoStore, nodeID string) (CertificateSnapshot, error) {
	domains, err := store.Domains(ctx)
	if err != nil {
		return CertificateSnapshot{}, err
	}
	return certificateSnapshotForNode(domains, nodeID), nil
}

func certificateSnapshotForNode(domains []dbDomain, nodeID string) CertificateSnapshot {
	out := make([]DomainCert, 0, len(domains))
	now := time.Now().UTC()
	for _, d := range domains {
		if !domainAssignedToNode(d, nodeID) {
			continue
		}
		if !domainCertificateUsable(d.Certificate, now) {
			continue
		}
		out = append(out, DomainCert{
			Domain:        d.Domain,
			FullchainPEM:  d.Certificate.FullchainPEM,
			PrivateKeyPEM: d.Certificate.PrivateKeyPEM,
			ExpiresAt:     d.Certificate.ExpiresAt,
		})
	}
	version, updatedAt := certsVersion(out)
	return CertificateSnapshot{
		CertVersion: version,
		Domains:     out,
		UpdatedAt:   updatedAt,
	}
}

func domainCertificateUsable(cert domainCertificate, now time.Time) bool {
	if strings.TrimSpace(cert.FullchainPEM) == "" || strings.TrimSpace(cert.PrivateKeyPEM) == "" {
		return false
	}
	if cert.ExpiresAt == nil || !cert.ExpiresAt.After(now) {
		return false
	}
	return true
}

func domainAssignedToNode(d dbDomain, nodeID string) bool {
	if !d.Enabled || nodeID == "" {
		return false
	}
	for _, id := range d.NodeIDs {
		if id == nodeID {
			return true
		}
	}
	return false
}

func certsVersion(certs []DomainCert) (string, time.Time) {
	sort.Slice(certs, func(i, j int) bool { return certs[i].Domain < certs[j].Domain })
	var latest time.Time
	h := sha256.New()
	for _, cert := range certs {
		if cert.ExpiresAt != nil && cert.ExpiresAt.After(latest) {
			latest = cert.ExpiresAt.UTC()
		}
		fmt.Fprintf(h, "d:%s\nc:%s\nk:%s\n", cert.Domain, cert.FullchainPEM, cert.PrivateKeyPEM)
		if cert.ExpiresAt != nil {
			fmt.Fprintf(h, "e:%s\n", cert.ExpiresAt.UTC().Format(time.RFC3339Nano))
		}
	}
	if latest.IsZero() {
		latest = time.Unix(0, 0).UTC()
	}
	return hex.EncodeToString(h.Sum(nil)), latest.UTC()
}

func certificateVersion(cert DomainCert) string {
	version, _ := certsVersion([]DomainCert{cert})
	return version
}

func versionETag(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	return `"` + strings.ReplaceAll(version, `"`, "") + `"`
}

func certSnapshotETag(version string) string {
	return versionETag(version)
}

func versionNotModified(r *http.Request, version string) bool {
	etag := versionETag(version)
	if etag == "" {
		return false
	}
	for _, candidate := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.Trim(candidate, `"`) == strings.Trim(etag, `"`) {
			return true
		}
	}
	return false
}

func certSnapshotNotModified(r *http.Request, version string) bool {
	return versionNotModified(r, version)
}

func certificateFailure(current domainCertificate, err error) domainCertificate {
	if err != nil {
		current.LastError = err.Error()
	}
	return current
}

func importedDomainCertificate(domain, fullchainPEM, privateKeyPEM string) (domainCertificate, error) {
	domain, err := normalizeDomainName(domain)
	if err != nil {
		return domainCertificate{}, err
	}
	fullchainPEM = strings.TrimSpace(fullchainPEM)
	privateKeyPEM = strings.TrimSpace(privateKeyPEM)
	if fullchainPEM == "" {
		return domainCertificate{}, fmt.Errorf("fullchain PEM is required")
	}
	if privateKeyPEM == "" {
		return domainCertificate{}, fmt.Errorf("private key PEM is required")
	}
	leaf, err := parseLeafCertificate(fullchainPEM)
	if err != nil {
		return domainCertificate{}, err
	}
	if _, err := tls.X509KeyPair([]byte(fullchainPEM), []byte(privateKeyPEM)); err != nil {
		return domainCertificate{}, fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	if !certificateCoversDomain(leaf, domain) {
		return domainCertificate{}, fmt.Errorf("certificate does not cover domain %s", domain)
	}
	if err := validateLeafCertificateTime(leaf, time.Now().UTC()); err != nil {
		return domainCertificate{}, err
	}
	expiresAt := leaf.NotAfter.UTC()
	now := time.Now().UTC()
	cert := domainCertificate{
		FullchainPEM:  fullchainPEM + "\n",
		PrivateKeyPEM: privateKeyPEM + "\n",
		IssuedAt:      &now,
		ExpiresAt:     &expiresAt,
		LastIssuedAt:  &now,
		LastError:     "",
	}
	cert.Version = certificateVersion(DomainCert{
		Domain:        domain,
		FullchainPEM:  cert.FullchainPEM,
		PrivateKeyPEM: cert.PrivateKeyPEM,
		ExpiresAt:     cert.ExpiresAt,
	})
	return cert, nil
}

func parseLeafCertificateExpiry(fullchainPEM string) (*time.Time, error) {
	cert, err := parseLeafCertificate(fullchainPEM)
	if err != nil {
		return nil, err
	}
	expiresAt := cert.NotAfter.UTC()
	return &expiresAt, nil
}

func parseLeafCertificate(fullchainPEM string) (*x509.Certificate, error) {
	rest := []byte(fullchainPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no certificate PEM block found")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
}

func certificateCoversDomain(cert *x509.Certificate, domain string) bool {
	if cert == nil {
		return false
	}
	domain, err := normalizeDomainName(domain)
	if err != nil {
		return false
	}
	if len(cert.DNSNames) > 0 {
		for _, name := range cert.DNSNames {
			if certificateNameMatchesDomain(name, domain) {
				return true
			}
		}
		return false
	}
	return certificateNameMatchesDomain(cert.Subject.CommonName, domain)
}

func certificateNameMatchesDomain(name, domain string) bool {
	name, err := normalizeDomainName(name)
	if err != nil {
		return false
	}
	if name == domain {
		return true
	}
	if !strings.HasPrefix(name, "*.") || strings.HasPrefix(domain, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(name, "*.")
	if !strings.HasSuffix(domain, "."+suffix) {
		return false
	}
	label := strings.TrimSuffix(domain, "."+suffix)
	return label != "" && !strings.Contains(label, ".")
}

func validateLeafCertificateTime(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("certificate is empty")
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(cert.NotAfter) {
		return fmt.Errorf("certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func writeCertificateSnapshot(cacheDir, certDir string, snap CertificateSnapshot) error {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return err
	}
	if err := writeCertificateFiles(certDir, snap.Domains); err != nil {
		return err
	}
	path := filepath.Join(cacheDir, certsSnapshotFileName)
	tmp, err := os.CreateTemp(cacheDir, "."+certsSnapshotFileName+".tmp-*")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func loadCertificateSnapshot(cacheDir string) (CertificateSnapshot, error) {
	f, err := os.Open(filepath.Join(cacheDir, certsSnapshotFileName))
	if err != nil {
		return CertificateSnapshot{}, err
	}
	defer f.Close()
	var snap CertificateSnapshot
	if err := json.NewDecoder(f).Decode(&snap); err != nil {
		return CertificateSnapshot{}, err
	}
	return snap, nil
}

func writeCertificateFiles(certDir string, certs []DomainCert) error {
	if certDir == "" {
		certDir = defaultCertCacheDir
	}
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	type pendingCertFile struct {
		domain string
		cert   DomainCert
	}
	assigned := make(map[string]struct{}, len(certs))
	pending := make([]pendingCertFile, 0, len(certs))
	for _, cert := range certs {
		domain, err := normalizeDomainName(cert.Domain)
		if err != nil {
			return err
		}
		assigned[domain] = struct{}{}
		if _, err := tls.X509KeyPair([]byte(cert.FullchainPEM), []byte(cert.PrivateKeyPEM)); err != nil {
			return fmt.Errorf("invalid certificate pair for %s: %w", domain, err)
		}
		leaf, err := parseLeafCertificate(cert.FullchainPEM)
		if err != nil {
			return fmt.Errorf("invalid certificate for %s: %w", domain, err)
		}
		if !certificateCoversDomain(leaf, domain) {
			return fmt.Errorf("certificate does not cover domain %s", domain)
		}
		if err := validateLeafCertificateTime(leaf, time.Now().UTC()); err != nil {
			return fmt.Errorf("invalid certificate for %s: %w", domain, err)
		}
		pending = append(pending, pendingCertFile{domain: domain, cert: cert})
	}
	for _, item := range pending {
		dir := filepath.Join(certDir, item.domain)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(dir, "fullchain.pem"), []byte(item.cert.FullchainPEM), 0o600); err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(dir, "privkey.pem"), []byte(item.cert.PrivateKeyPEM), 0o600); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(certDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, ok := assigned[entry.Name()]; ok {
			continue
		}
		_ = os.RemoveAll(filepath.Join(certDir, entry.Name()))
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func normalizeDomain(d *dbDomain) error {
	domain, err := normalizeDomainName(d.Domain)
	if err != nil {
		return err
	}
	d.Domain = domain
	if strings.TrimSpace(d.DNSProvider) == "" {
		d.DNSProvider = "cloudflare"
	}
	if d.RenewBeforeDays <= 0 {
		d.RenewBeforeDays = 30
	}
	d.FailoverPolicy = failoverPolicyWithDefaults(d.FailoverPolicy)
	if d.Cloudflare.TTL < 0 {
		return fmt.Errorf("cloudflare ttl must be zero or positive")
	}
	if d.Cloudflare.TTL == 0 {
		d.Cloudflare.TTL = 1
	}
	d.Cloudflare.ZoneID = strings.TrimSpace(d.Cloudflare.ZoneID)
	d.Cloudflare.ZoneName = strings.TrimSpace(d.Cloudflare.ZoneName)
	recordName := strings.TrimSpace(d.Cloudflare.RecordName)
	if recordName == "" {
		d.Cloudflare.RecordName = d.Domain
	} else {
		normalizedRecordName, err := normalizeDomainName(recordName)
		if err != nil {
			return err
		}
		d.Cloudflare.RecordName = normalizedRecordName
	}
	d.Cloudflare.RecordType = strings.ToUpper(strings.TrimSpace(d.Cloudflare.RecordType))
	switch d.Cloudflare.RecordType {
	case "", "A", "AAAA":
	default:
		return fmt.Errorf("unsupported cloudflare record type %q", d.Cloudflare.RecordType)
	}
	d.NodeIDs = uniqueNonEmpty(d.NodeIDs)
	d.FailoverPolicy.PrimaryNodeID = strings.TrimSpace(d.FailoverPolicy.PrimaryNodeID)
	if d.FailoverPolicy.PrimaryNodeID == "" && len(d.NodeIDs) > 0 {
		d.FailoverPolicy.PrimaryNodeID = d.NodeIDs[0]
	}
	if d.FailoverPolicy.PrimaryNodeID != "" && !stringInSlice(d.NodeIDs, d.FailoverPolicy.PrimaryNodeID) {
		return fmt.Errorf("primary node %q is not assigned to domain %s", d.FailoverPolicy.PrimaryNodeID, d.Domain)
	}
	d.ActiveNodeID = strings.TrimSpace(d.ActiveNodeID)
	if len(d.NodeIDs) == 0 {
		d.ActiveNodeID = ""
	} else if d.ActiveNodeID == "" {
		d.ActiveNodeID = d.NodeIDs[0]
	} else if !domainAssignedToNode(*d, d.ActiveNodeID) {
		return fmt.Errorf("active node %q is not assigned to domain %s", d.ActiveNodeID, d.Domain)
	}
	return nil
}

func stringInSlice(values []string, value string) bool {
	value = strings.TrimSpace(value)
	for _, candidate := range values {
		if strings.TrimSpace(candidate) == value {
			return true
		}
	}
	return false
}

var domainNameRe = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

func normalizeDomainName(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !domainNameRe.MatchString(domain) {
		return "", fmt.Errorf("invalid domain name")
	}
	return domain, nil
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
