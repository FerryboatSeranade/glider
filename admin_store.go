package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	usersCollection    = "users"
	rulesCollection    = "rules"
	nodesCollection    = "nodes"
	domainsCollection  = "domains"
	healthCollection   = "health"
	settingsCollection = "settings"

	cloudflareSettingsID = "cloudflare"
	rulesHealthID        = "rules"
)

type dbUser struct {
	Username  string     `bson:"username" json:"username"`
	Password  string     `bson:"password" json:"password"`
	Rule      string     `bson:"rule" json:"rule"`
	Enabled   *bool      `bson:"enabled,omitempty" json:"enabled,omitempty"`
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	UpdatedAt time.Time  `bson:"updated_at" json:"updated_at"`
}

type dbRule struct {
	Name      string    `bson:"name" json:"name"`
	Content   string    `bson:"content" json:"content"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

type NodeHeartbeat struct {
	NodeID        string          `bson:"node_id" json:"node_id"`
	Hostname      string          `bson:"hostname,omitempty" json:"hostname,omitempty"`
	PublicIP      string          `bson:"public_ip,omitempty" json:"public_ip,omitempty"`
	GliderVersion string          `bson:"glider_version,omitempty" json:"glider_version,omitempty"`
	ConfigVersion string          `bson:"config_version,omitempty" json:"config_version,omitempty"`
	CertVersion   string          `bson:"cert_version,omitempty" json:"cert_version,omitempty"`
	CertDomains   []NodeCertState `bson:"cert_domains,omitempty" json:"cert_domains,omitempty"`
	CertError     string          `bson:"cert_error,omitempty" json:"cert_error,omitempty"`
	Uptime        int64           `bson:"uptime,omitempty" json:"uptime,omitempty"`
	RXBytes       uint64          `bson:"rx_bytes,omitempty" json:"rx_bytes,omitempty"`
	TXBytes       uint64          `bson:"tx_bytes,omitempty" json:"tx_bytes,omitempty"`
	Traffic       TrafficSnapshot `bson:"traffic,omitempty" json:"traffic,omitempty"`
	Error         string          `bson:"error,omitempty" json:"error,omitempty"`
	UpdatedAt     time.Time       `bson:"updated_at" json:"updated_at"`
	AuthMode      string          `bson:"auth_mode,omitempty" json:"auth_mode,omitempty"`
	HasToken      bool            `bson:"-" json:"has_token,omitempty"`
	TokenSetAt    *time.Time      `bson:"token_set_at,omitempty" json:"token_set_at,omitempty"`
	TokenHash     string          `bson:"token_hash,omitempty" json:"-"`
}

type NodeCertState struct {
	Domain    string     `bson:"domain" json:"domain"`
	Version   string     `bson:"version,omitempty" json:"version,omitempty"`
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
}

type dbDomain struct {
	Domain          string                 `bson:"domain" json:"domain"`
	Enabled         bool                   `bson:"enabled" json:"enabled"`
	NodeIDs         []string               `bson:"node_ids,omitempty" json:"node_ids,omitempty"`
	ActiveNodeID    string                 `bson:"active_node_id,omitempty" json:"active_node_id,omitempty"`
	FailoverEnabled bool                   `bson:"failover_enabled,omitempty" json:"failover_enabled,omitempty"`
	RenewBeforeDays int                    `bson:"renew_before_days,omitempty" json:"renew_before_days,omitempty"`
	DNSProvider     string                 `bson:"dns_provider,omitempty" json:"dns_provider,omitempty"`
	Cloudflare      cloudflareDomainConfig `bson:"cloudflare,omitempty" json:"cloudflare,omitempty"`
	Certificate     domainCertificate      `bson:"certificate,omitempty" json:"certificate,omitempty"`
	UpdatedAt       time.Time              `bson:"updated_at" json:"updated_at"`
}

type cloudflareDomainConfig struct {
	ZoneID       string     `bson:"zone_id,omitempty" json:"zone_id,omitempty"`
	ZoneName     string     `bson:"zone_name,omitempty" json:"zone_name,omitempty"`
	RecordID     string     `bson:"record_id,omitempty" json:"record_id,omitempty"`
	RecordName   string     `bson:"record_name,omitempty" json:"record_name,omitempty"`
	RecordType   string     `bson:"record_type,omitempty" json:"record_type,omitempty"`
	TTL          int        `bson:"ttl,omitempty" json:"ttl,omitempty"`
	Proxied      bool       `bson:"proxied,omitempty" json:"proxied,omitempty"`
	LastSyncedAt *time.Time `bson:"last_synced_at,omitempty" json:"last_synced_at,omitempty"`
	LastError    string     `bson:"last_error,omitempty" json:"last_error,omitempty"`
}

type domainCertificate struct {
	Version       string     `bson:"version,omitempty" json:"version,omitempty"`
	FullchainPEM  string     `bson:"fullchain_pem,omitempty" json:"fullchain_pem,omitempty"`
	PrivateKeyPEM string     `bson:"private_key_pem,omitempty" json:"private_key_pem,omitempty"`
	IssuedAt      *time.Time `bson:"issued_at,omitempty" json:"issued_at,omitempty"`
	ExpiresAt     *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	LastIssuedAt  *time.Time `bson:"last_issued_at,omitempty" json:"last_issued_at,omitempty"`
	LastError     string     `bson:"last_error,omitempty" json:"last_error,omitempty"`
}

type cloudflareSettings struct {
	ID               string    `bson:"_id,omitempty" json:"-"`
	APIToken         string    `bson:"api_token,omitempty" json:"-"`
	AccountID        string    `bson:"account_id,omitempty" json:"account_id,omitempty"`
	ACMEEmail        string    `bson:"acme_email,omitempty" json:"acme_email,omitempty"`
	ACMEDirectoryURL string    `bson:"acme_directory_url,omitempty" json:"acme_directory_url,omitempty"`
	UpdatedAt        time.Time `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
	Source           string    `bson:"-" json:"-"`
}

type rulesHealthDocument struct {
	ID        string          `bson:"_id,omitempty"`
	CheckedAt time.Time       `bson:"checked_at" json:"checked_at"`
	Target    string          `bson:"target" json:"target"`
	Timeout   string          `bson:"timeout,omitempty" json:"timeout,omitempty"`
	Results   []checkResponse `bson:"results" json:"results"`
	UpdatedAt time.Time       `bson:"updated_at" json:"updated_at"`
}

type mongoStore struct {
	client *mongo.Client
	db     *mongo.Database
}

func newMongoStore(ctx context.Context, uri, dbName string) (*mongoStore, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	store := &mongoStore{
		client: client,
		db:     client.Database(dbName),
	}
	if err := store.ensureIndexes(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *mongoStore) ensureIndexes(ctx context.Context) error {
	users := s.db.Collection(usersCollection)
	rules := s.db.Collection(rulesCollection)
	nodes := s.db.Collection(nodesCollection)
	domains := s.db.Collection(domainsCollection)

	_, err := users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	_, err = rules.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	if _, err = nodes.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "node_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}

	_, err = domains.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "domain", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func (s *mongoStore) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}

func (s *mongoStore) Users(ctx context.Context) ([]dbUser, error) {
	cur, err := s.db.Collection(usersCollection).Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []dbUser
	for cur.Next(ctx) {
		var u dbUser
		if err := cur.Decode(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, cur.Err()
}

func (s *mongoStore) UpsertUser(ctx context.Context, u dbUser) error {
	u.UpdatedAt = time.Now()
	enabled := true
	if u.Enabled != nil {
		enabled = *u.Enabled
	}
	update := bson.M{
		"$set": bson.M{
			"username":   u.Username,
			"password":   u.Password,
			"rule":       u.Rule,
			"enabled":    enabled,
			"updated_at": u.UpdatedAt,
		},
	}
	if u.ExpiresAt != nil && !u.ExpiresAt.IsZero() {
		update["$set"].(bson.M)["expires_at"] = *u.ExpiresAt
	} else {
		update["$unset"] = bson.M{"expires_at": ""}
	}
	_, err := s.db.Collection(usersCollection).UpdateOne(ctx, bson.M{"username": u.Username}, update, options.Update().SetUpsert(true))
	return err
}

func (s *mongoStore) DeleteUser(ctx context.Context, username string) error {
	_, err := s.db.Collection(usersCollection).DeleteOne(ctx, bson.M{"username": username})
	return err
}

func (s *mongoStore) Rules(ctx context.Context) ([]dbRule, error) {
	cur, err := s.db.Collection(rulesCollection).Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []dbRule
	for cur.Next(ctx) {
		var r dbRule
		if err := cur.Decode(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, cur.Err()
}

func (s *mongoStore) GetRule(ctx context.Context, name string) (*dbRule, error) {
	var r dbRule
	err := s.db.Collection(rulesCollection).FindOne(ctx, bson.M{"name": name}).Decode(&r)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("rule not found")
	}
	return &r, err
}

func (s *mongoStore) UpsertRule(ctx context.Context, r dbRule) error {
	r.UpdatedAt = time.Now()
	update := bson.M{
		"$set": bson.M{
			"name":       r.Name,
			"content":    r.Content,
			"updated_at": r.UpdatedAt,
		},
	}
	_, err := s.db.Collection(rulesCollection).UpdateOne(ctx, bson.M{"name": r.Name}, update, options.Update().SetUpsert(true))
	return err
}

func (s *mongoStore) DeleteRule(ctx context.Context, name string) error {
	_, err := s.db.Collection(rulesCollection).DeleteOne(ctx, bson.M{"name": name})
	return err
}

func (s *mongoStore) UpsertNodeHeartbeat(ctx context.Context, h NodeHeartbeat) error {
	if h.UpdatedAt.IsZero() {
		h.UpdatedAt = time.Now().UTC()
	}
	update := bson.M{
		"$set": bson.M{
			"node_id":        h.NodeID,
			"hostname":       h.Hostname,
			"public_ip":      h.PublicIP,
			"glider_version": h.GliderVersion,
			"config_version": h.ConfigVersion,
			"cert_version":   h.CertVersion,
			"cert_domains":   h.CertDomains,
			"cert_error":     h.CertError,
			"uptime":         h.Uptime,
			"rx_bytes":       h.RXBytes,
			"tx_bytes":       h.TXBytes,
			"traffic":        h.Traffic,
			"error":          h.Error,
			"auth_mode":      h.AuthMode,
			"updated_at":     h.UpdatedAt,
		},
	}
	_, err := s.db.Collection(nodesCollection).UpdateOne(ctx, bson.M{"node_id": h.NodeID}, update, options.Update().SetUpsert(true))
	return err
}

func (s *mongoStore) GetNode(ctx context.Context, nodeID string) (*NodeHeartbeat, error) {
	var h NodeHeartbeat
	err := s.db.Collection(nodesCollection).FindOne(ctx, bson.M{"node_id": nodeID}).Decode(&h)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("node not found")
	}
	h.HasToken = strings.TrimSpace(h.TokenHash) != ""
	return &h, err
}

func (s *mongoStore) Nodes(ctx context.Context) ([]NodeHeartbeat, error) {
	cur, err := s.db.Collection(nodesCollection).Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "updated_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []NodeHeartbeat
	for cur.Next(ctx) {
		var h NodeHeartbeat
		if err := cur.Decode(&h); err != nil {
			return nil, err
		}
		h.HasToken = strings.TrimSpace(h.TokenHash) != ""
		out = append(out, h)
	}
	return out, cur.Err()
}

func (s *mongoStore) DeleteNode(ctx context.Context, nodeID string) error {
	_, err := s.db.Collection(nodesCollection).DeleteOne(ctx, bson.M{"node_id": nodeID})
	return err
}

func (s *mongoStore) SetNodeTokenHash(ctx context.Context, nodeID, tokenHash string) error {
	now := time.Now().UTC()
	_, err := s.db.Collection(nodesCollection).UpdateOne(ctx, bson.M{"node_id": nodeID}, bson.M{
		"$set": bson.M{
			"node_id":      nodeID,
			"token_hash":   tokenHash,
			"token_set_at": now,
			"updated_at":   now,
		},
	}, options.Update().SetUpsert(true))
	return err
}

func (s *mongoStore) ClearNodeTokenHash(ctx context.Context, nodeID string) error {
	_, err := s.db.Collection(nodesCollection).UpdateOne(ctx, bson.M{"node_id": nodeID}, bson.M{
		"$unset": bson.M{
			"token_hash":   "",
			"token_set_at": "",
		},
		"$set": bson.M{
			"updated_at": time.Now().UTC(),
		},
	})
	return err
}

func (s *mongoStore) Domains(ctx context.Context) ([]dbDomain, error) {
	cur, err := s.db.Collection(domainsCollection).Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "domain", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []dbDomain
	for cur.Next(ctx) {
		var d dbDomain
		if err := cur.Decode(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, cur.Err()
}

func (s *mongoStore) GetDomain(ctx context.Context, domain string) (*dbDomain, error) {
	var d dbDomain
	err := s.db.Collection(domainsCollection).FindOne(ctx, bson.M{"domain": domain}).Decode(&d)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("domain not found")
	}
	return &d, err
}

func (s *mongoStore) UpsertDomain(ctx context.Context, d dbDomain) error {
	set, err := domainConfigSet(&d)
	if err != nil {
		return err
	}
	_, err = s.db.Collection(domainsCollection).UpdateOne(ctx, bson.M{"domain": d.Domain}, bson.M{"$set": set}, options.Update().SetUpsert(true))
	return err
}

func domainConfigSet(d *dbDomain) (bson.M, error) {
	if err := normalizeDomain(d); err != nil {
		return nil, err
	}
	d.UpdatedAt = time.Now().UTC()
	return bson.M{
		"domain":                 d.Domain,
		"enabled":                d.Enabled,
		"node_ids":               d.NodeIDs,
		"active_node_id":         d.ActiveNodeID,
		"failover_enabled":       d.FailoverEnabled,
		"renew_before_days":      d.RenewBeforeDays,
		"dns_provider":           d.DNSProvider,
		"cloudflare.zone_id":     d.Cloudflare.ZoneID,
		"cloudflare.record_name": d.Cloudflare.RecordName,
		"cloudflare.record_type": d.Cloudflare.RecordType,
		"cloudflare.ttl":         d.Cloudflare.TTL,
		"cloudflare.proxied":     d.Cloudflare.Proxied,
		"updated_at":             d.UpdatedAt,
	}, nil
}

func (s *mongoStore) DeleteDomain(ctx context.Context, domain string) error {
	_, err := s.db.Collection(domainsCollection).DeleteOne(ctx, bson.M{"domain": domain})
	return err
}

func (s *mongoStore) UpdateDomainCloudflare(ctx context.Context, domain string, cf cloudflareDomainConfig) error {
	_, err := s.db.Collection(domainsCollection).UpdateOne(ctx, bson.M{"domain": domain}, bson.M{
		"$set": bson.M{
			"cloudflare": cf,
			"updated_at": time.Now().UTC(),
		},
	})
	return err
}

func (s *mongoStore) UpdateDomainActiveNode(ctx context.Context, domain, nodeID string) error {
	_, err := s.db.Collection(domainsCollection).UpdateOne(ctx, bson.M{"domain": domain}, bson.M{
		"$set": bson.M{
			"active_node_id": nodeID,
			"updated_at":     time.Now().UTC(),
		},
	})
	return err
}

func (s *mongoStore) UpdateDomainCertificate(ctx context.Context, domain string, cert domainCertificate) error {
	_, err := s.db.Collection(domainsCollection).UpdateOne(ctx, bson.M{"domain": domain}, bson.M{
		"$set": bson.M{
			"certificate": cert,
			"updated_at":  time.Now().UTC(),
		},
	})
	return err
}

func (s *mongoStore) LatestRulesHealth(ctx context.Context) (*rulesHealthResponse, error) {
	var doc rulesHealthDocument
	err := s.db.Collection(healthCollection).FindOne(ctx, bson.M{"_id": rulesHealthID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rulesHealthResponse{
		CheckedAt: doc.CheckedAt,
		Target:    doc.Target,
		Timeout:   doc.Timeout,
		Results:   doc.Results,
	}, nil
}

func (s *mongoStore) SaveRulesHealth(ctx context.Context, health rulesHealthResponse) error {
	now := time.Now().UTC()
	if health.CheckedAt.IsZero() {
		health.CheckedAt = now
	}
	if health.Results == nil {
		health.Results = []checkResponse{}
	}
	_, err := s.db.Collection(healthCollection).UpdateOne(ctx, bson.M{"_id": rulesHealthID}, bson.M{
		"$set": bson.M{
			"checked_at": health.CheckedAt,
			"target":     health.Target,
			"timeout":    health.Timeout,
			"results":    health.Results,
			"updated_at": now,
		},
	}, options.Update().SetUpsert(true))
	return err
}

func (s *mongoStore) CloudflareSettings(ctx context.Context) (cloudflareSettings, error) {
	var settings cloudflareSettings
	err := s.db.Collection(settingsCollection).FindOne(ctx, bson.M{"_id": cloudflareSettingsID}).Decode(&settings)
	if err == mongo.ErrNoDocuments {
		return cloudflareSettings{ID: cloudflareSettingsID}, nil
	}
	if err != nil {
		return cloudflareSettings{}, err
	}
	settings.APIToken, err = decodeStoredSecret(settings.APIToken)
	if err != nil {
		return cloudflareSettings{}, err
	}
	return settings, err
}

func (s *mongoStore) UpdateCloudflareSettings(ctx context.Context, settings cloudflareSettings, apiToken *string, clearToken bool) error {
	update, err := cloudflareSettingsUpdate(settings, apiToken, clearToken, time.Now().UTC())
	if err != nil {
		return err
	}

	_, err = s.db.Collection(settingsCollection).UpdateOne(
		ctx,
		bson.M{"_id": cloudflareSettingsID},
		update,
		options.Update().SetUpsert(true),
	)
	return err
}

func cloudflareSettingsUpdate(settings cloudflareSettings, apiToken *string, clearToken bool, now time.Time) (bson.M, error) {
	set := bson.M{
		"account_id":         strings.TrimSpace(settings.AccountID),
		"acme_email":         strings.TrimSpace(settings.ACMEEmail),
		"acme_directory_url": strings.TrimSpace(settings.ACMEDirectoryURL),
		"updated_at":         now,
	}
	update := bson.M{"$set": set}

	if clearToken {
		update["$unset"] = bson.M{"api_token": ""}
	} else if apiToken != nil {
		token := strings.TrimSpace(*apiToken)
		if token != "" {
			storedToken, err := encodeStoredSecret(token)
			if err != nil {
				return nil, err
			}
			set["api_token"] = storedToken
		}
	}

	return update, nil
}
