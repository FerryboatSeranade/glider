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
	serversCollection  = "servers"
	jobsCollection     = "jobs"
	eventsCollection   = "events"
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
	NodeID          string          `bson:"node_id" json:"node_id"`
	Hostname        string          `bson:"hostname,omitempty" json:"hostname,omitempty"`
	PublicIP        string          `bson:"public_ip,omitempty" json:"public_ip,omitempty"`
	GliderVersion   string          `bson:"glider_version,omitempty" json:"glider_version,omitempty"`
	ConfigVersion   string          `bson:"config_version,omitempty" json:"config_version,omitempty"`
	CertVersion     string          `bson:"cert_version,omitempty" json:"cert_version,omitempty"`
	CertDomains     []NodeCertState `bson:"cert_domains,omitempty" json:"cert_domains,omitempty"`
	CertError       string          `bson:"cert_error,omitempty" json:"cert_error,omitempty"`
	Uptime          int64           `bson:"uptime,omitempty" json:"uptime,omitempty"`
	RXBytes         uint64          `bson:"rx_bytes,omitempty" json:"rx_bytes,omitempty"`
	TXBytes         uint64          `bson:"tx_bytes,omitempty" json:"tx_bytes,omitempty"`
	Traffic         TrafficSnapshot `bson:"traffic,omitempty" json:"traffic,omitempty"`
	Error           string          `bson:"error,omitempty" json:"error,omitempty"`
	ProxyStatus     string          `bson:"proxy_status,omitempty" json:"proxy_status,omitempty"`
	ProxyCheckedAt  *time.Time      `bson:"proxy_checked_at,omitempty" json:"proxy_checked_at,omitempty"`
	ProxyExitIP     string          `bson:"proxy_exit_ip,omitempty" json:"proxy_exit_ip,omitempty"`
	ProxyOrg        string          `bson:"proxy_org,omitempty" json:"proxy_org,omitempty"`
	ProxyHTTPStatus int             `bson:"proxy_http_status,omitempty" json:"proxy_http_status,omitempty"`
	ProxyDurationMS int64           `bson:"proxy_duration_ms,omitempty" json:"proxy_duration_ms,omitempty"`
	ProxyError      string          `bson:"proxy_error,omitempty" json:"proxy_error,omitempty"`
	UpdatedAt       time.Time       `bson:"updated_at" json:"updated_at"`
	AuthMode        string          `bson:"auth_mode,omitempty" json:"auth_mode,omitempty"`
	HasToken        bool            `bson:"-" json:"has_token,omitempty"`
	TokenSetAt      *time.Time      `bson:"token_set_at,omitempty" json:"token_set_at,omitempty"`
	TokenHash       string          `bson:"token_hash,omitempty" json:"-"`
}

type NodeCertState struct {
	Domain    string     `bson:"domain" json:"domain"`
	Version   string     `bson:"version,omitempty" json:"version,omitempty"`
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
}

type dbServer struct {
	ServerID       string     `bson:"server_id" json:"server_id"`
	Name           string     `bson:"name,omitempty" json:"name,omitempty"`
	NodeID         string     `bson:"node_id,omitempty" json:"node_id,omitempty"`
	Host           string     `bson:"host" json:"host"`
	SSHPort        int        `bson:"ssh_port,omitempty" json:"ssh_port,omitempty"`
	SSHUser        string     `bson:"ssh_user,omitempty" json:"ssh_user,omitempty"`
	AuthType       string     `bson:"auth_type,omitempty" json:"auth_type,omitempty"`
	Password       string     `bson:"password,omitempty" json:"-"`
	PrivateKey     string     `bson:"private_key,omitempty" json:"-"`
	Passphrase     string     `bson:"passphrase,omitempty" json:"-"`
	DeployDir      string     `bson:"deploy_dir,omitempty" json:"deploy_dir,omitempty"`
	Image          string     `bson:"image,omitempty" json:"image,omitempty"`
	ProxyPorts     []string   `bson:"proxy_ports,omitempty" json:"proxy_ports,omitempty"`
	CertHostPath   string     `bson:"cert_host_path,omitempty" json:"cert_host_path,omitempty"`
	TrafficIface   string     `bson:"traffic_iface,omitempty" json:"traffic_iface,omitempty"`
	Status         string     `bson:"status,omitempty" json:"status,omitempty"`
	LastError      string     `bson:"last_error,omitempty" json:"last_error,omitempty"`
	LastTestAt     *time.Time `bson:"last_test_at,omitempty" json:"last_test_at,omitempty"`
	LastDeployAt   *time.Time `bson:"last_deploy_at,omitempty" json:"last_deploy_at,omitempty"`
	LastDeployJob  string     `bson:"last_deploy_job,omitempty" json:"last_deploy_job,omitempty"`
	CreatedAt      time.Time  `bson:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt      time.Time  `bson:"updated_at" json:"updated_at"`
	HasPassword    bool       `bson:"-" json:"has_password,omitempty"`
	HasPrivateKey  bool       `bson:"-" json:"has_private_key,omitempty"`
	HasPassphrase  bool       `bson:"-" json:"has_passphrase,omitempty"`
	MaskedPassword string     `bson:"-" json:"masked_password,omitempty"`
	MaskedKey      string     `bson:"-" json:"masked_key,omitempty"`
}

type serverSecretUpdate struct {
	Password        *string
	PrivateKey      *string
	Passphrase      *string
	ClearPassword   bool
	ClearPrivateKey bool
	ClearPassphrase bool
}

type dbJob struct {
	JobID      string       `bson:"job_id" json:"job_id"`
	Type       string       `bson:"type" json:"type"`
	Status     string       `bson:"status" json:"status"`
	ServerID   string       `bson:"server_id,omitempty" json:"server_id,omitempty"`
	NodeID     string       `bson:"node_id,omitempty" json:"node_id,omitempty"`
	Domain     string       `bson:"domain,omitempty" json:"domain,omitempty"`
	CreatedAt  time.Time    `bson:"created_at" json:"created_at"`
	StartedAt  *time.Time   `bson:"started_at,omitempty" json:"started_at,omitempty"`
	FinishedAt *time.Time   `bson:"finished_at,omitempty" json:"finished_at,omitempty"`
	Error      string       `bson:"error,omitempty" json:"error,omitempty"`
	Logs       []dbJobLog   `bson:"logs,omitempty" json:"logs,omitempty"`
	Request    dbJobRequest `bson:"request,omitempty" json:"request,omitempty"`
}

type dbJobLog struct {
	At      time.Time `bson:"at" json:"at"`
	Message string    `bson:"message" json:"message"`
}

type dbJobRequest struct {
	CentralURL           string   `bson:"central_url,omitempty" json:"central_url,omitempty"`
	Image                string   `bson:"image,omitempty" json:"image,omitempty"`
	DeployDir            string   `bson:"deploy_dir,omitempty" json:"deploy_dir,omitempty"`
	ProxyPorts           []string `bson:"proxy_ports,omitempty" json:"proxy_ports,omitempty"`
	InstallDocker        bool     `bson:"install_docker,omitempty" json:"install_docker,omitempty"`
	SyncInterval         string   `bson:"sync_interval,omitempty" json:"sync_interval,omitempty"`
	WaitHeartbeatSeconds int      `bson:"wait_heartbeat_seconds,omitempty" json:"wait_heartbeat_seconds,omitempty"`
}

type dbEvent struct {
	EventID   string         `bson:"event_id" json:"event_id"`
	Type      string         `bson:"type" json:"type"`
	Severity  string         `bson:"severity,omitempty" json:"severity,omitempty"`
	Actor     string         `bson:"actor,omitempty" json:"actor,omitempty"`
	Message   string         `bson:"message" json:"message"`
	ServerID  string         `bson:"server_id,omitempty" json:"server_id,omitempty"`
	NodeID    string         `bson:"node_id,omitempty" json:"node_id,omitempty"`
	Domain    string         `bson:"domain,omitempty" json:"domain,omitempty"`
	JobID     string         `bson:"job_id,omitempty" json:"job_id,omitempty"`
	Metadata  map[string]any `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt time.Time      `bson:"created_at" json:"created_at"`
}

type dbDomain struct {
	Domain          string                 `bson:"domain" json:"domain"`
	Enabled         bool                   `bson:"enabled" json:"enabled"`
	NodeIDs         []string               `bson:"node_ids,omitempty" json:"node_ids,omitempty"`
	ActiveNodeID    string                 `bson:"active_node_id,omitempty" json:"active_node_id,omitempty"`
	FailoverEnabled bool                   `bson:"failover_enabled,omitempty" json:"failover_enabled,omitempty"`
	FailoverPolicy  domainFailoverPolicy   `bson:"failover_policy,omitempty" json:"failover_policy,omitempty"`
	FailoverState   domainFailoverState    `bson:"failover_state,omitempty" json:"failover_state,omitempty"`
	RenewBeforeDays int                    `bson:"renew_before_days,omitempty" json:"renew_before_days,omitempty"`
	DNSProvider     string                 `bson:"dns_provider,omitempty" json:"dns_provider,omitempty"`
	Cloudflare      cloudflareDomainConfig `bson:"cloudflare,omitempty" json:"cloudflare,omitempty"`
	Certificate     domainCertificate      `bson:"certificate,omitempty" json:"certificate,omitempty"`
	UpdatedAt       time.Time              `bson:"updated_at" json:"updated_at"`
}

type domainFailoverPolicy struct {
	FailThreshold   int    `bson:"fail_threshold,omitempty" json:"fail_threshold,omitempty"`
	CooldownSeconds int    `bson:"cooldown_seconds,omitempty" json:"cooldown_seconds,omitempty"`
	ManualLock      bool   `bson:"manual_lock,omitempty" json:"manual_lock,omitempty"`
	AutoFailback    bool   `bson:"auto_failback,omitempty" json:"auto_failback,omitempty"`
	PrimaryNodeID   string `bson:"primary_node_id,omitempty" json:"primary_node_id,omitempty"`
}

type domainFailoverState struct {
	ActiveFailureCount int        `bson:"active_failure_count,omitempty" json:"active_failure_count,omitempty"`
	LastCheckAt        *time.Time `bson:"last_check_at,omitempty" json:"last_check_at,omitempty"`
	LastFailureAt      *time.Time `bson:"last_failure_at,omitempty" json:"last_failure_at,omitempty"`
	LastSwitchAt       *time.Time `bson:"last_switch_at,omitempty" json:"last_switch_at,omitempty"`
	CooldownUntil      *time.Time `bson:"cooldown_until,omitempty" json:"cooldown_until,omitempty"`
	LastFromNodeID     string     `bson:"last_from_node_id,omitempty" json:"last_from_node_id,omitempty"`
	LastToNodeID       string     `bson:"last_to_node_id,omitempty" json:"last_to_node_id,omitempty"`
	LastReason         string     `bson:"last_reason,omitempty" json:"last_reason,omitempty"`
	LastError          string     `bson:"last_error,omitempty" json:"last_error,omitempty"`
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
	servers := s.db.Collection(serversCollection)
	jobs := s.db.Collection(jobsCollection)
	events := s.db.Collection(eventsCollection)
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

	if _, err = servers.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "server_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}

	if _, err = jobs.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "job_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	if _, err = jobs.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: -1}},
	}); err != nil {
		return err
	}

	if _, err = events.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "event_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	if _, err = events.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: -1}},
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

func (s *mongoStore) UpdateNodeProxyProbe(ctx context.Context, nodeID string, probe NodeProxyProbe) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return fmt.Errorf("node_id required")
	}
	if probe.CheckedAt.IsZero() {
		probe.CheckedAt = time.Now().UTC()
	}
	set := bson.M{
		"node_id":           nodeID,
		"proxy_status":      probe.Status,
		"proxy_checked_at":  probe.CheckedAt,
		"proxy_exit_ip":     probe.ExitIP,
		"proxy_org":         probe.Org,
		"proxy_http_status": probe.HTTPStatus,
		"proxy_duration_ms": probe.DurationMS,
		"proxy_error":       probe.Error,
	}
	_, err := s.db.Collection(nodesCollection).UpdateOne(ctx, bson.M{"node_id": nodeID}, bson.M{"$set": set})
	return err
}

func (s *mongoStore) Servers(ctx context.Context) ([]dbServer, error) {
	cur, err := s.db.Collection(serversCollection).Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "server_id", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []dbServer
	for cur.Next(ctx) {
		var srv dbServer
		if err := cur.Decode(&srv); err != nil {
			return nil, err
		}
		out = append(out, redactServerSecrets(srv))
	}
	return out, cur.Err()
}

func (s *mongoStore) GetServer(ctx context.Context, serverID string) (*dbServer, error) {
	var srv dbServer
	err := s.db.Collection(serversCollection).FindOne(ctx, bson.M{"server_id": serverID}).Decode(&srv)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("server not found")
	}
	if err != nil {
		return nil, err
	}
	srv, err = decodeServerSecrets(srv)
	if err != nil {
		return nil, err
	}
	return &srv, nil
}

func (s *mongoStore) UpsertServer(ctx context.Context, srv dbServer, secrets serverSecretUpdate) error {
	normalized := srv
	if err := normalizeServer(&normalized); err != nil {
		return err
	}
	now := time.Now().UTC()
	set, unset, err := serverUpdateDocument(normalized, secrets, now)
	if err != nil {
		return err
	}
	update := bson.M{
		"$set":         set,
		"$setOnInsert": bson.M{"created_at": now},
	}
	if len(unset) > 0 {
		update["$unset"] = unset
	}
	_, err = s.db.Collection(serversCollection).UpdateOne(ctx, bson.M{"server_id": normalized.ServerID}, update, options.Update().SetUpsert(true))
	return err
}

func serverUpdateDocument(srv dbServer, secrets serverSecretUpdate, now time.Time) (bson.M, bson.M, error) {
	if err := normalizeServer(&srv); err != nil {
		return nil, nil, err
	}
	set := bson.M{
		"server_id":      srv.ServerID,
		"name":           strings.TrimSpace(srv.Name),
		"node_id":        strings.TrimSpace(srv.NodeID),
		"host":           strings.TrimSpace(srv.Host),
		"ssh_port":       srv.SSHPort,
		"ssh_user":       strings.TrimSpace(srv.SSHUser),
		"auth_type":      strings.TrimSpace(srv.AuthType),
		"deploy_dir":     strings.TrimSpace(srv.DeployDir),
		"image":          strings.TrimSpace(srv.Image),
		"proxy_ports":    normalizeStringList(srv.ProxyPorts),
		"cert_host_path": strings.TrimSpace(srv.CertHostPath),
		"traffic_iface":  strings.TrimSpace(srv.TrafficIface),
		"updated_at":     now,
	}
	unset := bson.M{}
	if secrets.ClearPassword {
		unset["password"] = ""
	} else if secrets.Password != nil {
		encoded, err := encodeStoredSecret(*secrets.Password)
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(encoded) == "" {
			unset["password"] = ""
		} else {
			set["password"] = encoded
		}
	}
	if secrets.ClearPrivateKey {
		unset["private_key"] = ""
	} else if secrets.PrivateKey != nil {
		encoded, err := encodeStoredSecret(*secrets.PrivateKey)
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(encoded) == "" {
			unset["private_key"] = ""
		} else {
			set["private_key"] = encoded
		}
	}
	if secrets.ClearPassphrase {
		unset["passphrase"] = ""
	} else if secrets.Passphrase != nil {
		encoded, err := encodeStoredSecret(*secrets.Passphrase)
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(encoded) == "" {
			unset["passphrase"] = ""
		} else {
			set["passphrase"] = encoded
		}
	}
	return set, unset, nil
}

func normalizeServer(srv *dbServer) error {
	srv.ServerID = strings.TrimSpace(srv.ServerID)
	if srv.ServerID == "" {
		return fmt.Errorf("server_id required")
	}
	if strings.ContainsAny(srv.ServerID, `/\?#`) {
		return fmt.Errorf("server_id contains invalid characters")
	}
	srv.Host = strings.TrimSpace(srv.Host)
	if srv.Host == "" {
		return fmt.Errorf("host required")
	}
	if srv.SSHPort <= 0 {
		srv.SSHPort = 22
	}
	if srv.SSHUser = strings.TrimSpace(srv.SSHUser); srv.SSHUser == "" {
		srv.SSHUser = "root"
	}
	srv.AuthType = normalizeServerAuthType(srv.AuthType)
	if srv.AuthType == "" {
		srv.AuthType = "auto"
	}
	switch srv.AuthType {
	case "auto", "password", "private_key":
	default:
		return fmt.Errorf("unsupported auth_type %q", srv.AuthType)
	}
	if srv.NodeID = strings.TrimSpace(srv.NodeID); srv.NodeID == "" {
		srv.NodeID = srv.ServerID
	}
	if srv.DeployDir = strings.TrimSpace(srv.DeployDir); srv.DeployDir == "" {
		srv.DeployDir = "/root/data/docker_data/glider"
	}
	if srv.TrafficIface = strings.TrimSpace(srv.TrafficIface); srv.TrafficIface == "" {
		srv.TrafficIface = "eth0"
	}
	if len(srv.ProxyPorts) == 0 {
		srv.ProxyPorts = []string{"443:443", "8443:8443"}
	}
	return nil
}

func normalizeServerAuthType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "key", "private-key", "privatekey", "ssh_key", "ssh-key":
		return "private_key"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
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

func decodeServerSecrets(srv dbServer) (dbServer, error) {
	var err error
	if srv.Password, err = decodeStoredSecret(srv.Password); err != nil {
		return srv, err
	}
	if srv.PrivateKey, err = decodeStoredSecret(srv.PrivateKey); err != nil {
		return srv, err
	}
	if srv.Passphrase, err = decodeStoredSecret(srv.Passphrase); err != nil {
		return srv, err
	}
	return srv, nil
}

func redactServerSecrets(srv dbServer) dbServer {
	srv.HasPassword = strings.TrimSpace(srv.Password) != ""
	srv.HasPrivateKey = strings.TrimSpace(srv.PrivateKey) != ""
	srv.HasPassphrase = strings.TrimSpace(srv.Passphrase) != ""
	srv.MaskedPassword = maskSecret(srv.Password)
	if srv.HasPrivateKey {
		srv.MaskedKey = "configured"
	}
	srv.Password = ""
	srv.PrivateKey = ""
	srv.Passphrase = ""
	return srv
}

func (s *mongoStore) DeleteServer(ctx context.Context, serverID string) error {
	_, err := s.db.Collection(serversCollection).DeleteOne(ctx, bson.M{"server_id": serverID})
	return err
}

func (s *mongoStore) UpdateServerStatus(ctx context.Context, serverID, status, lastError string, testAt, deployAt *time.Time, deployJob string) error {
	set := bson.M{
		"status":     status,
		"last_error": lastError,
		"updated_at": time.Now().UTC(),
	}
	if testAt != nil {
		set["last_test_at"] = *testAt
	}
	if deployAt != nil {
		set["last_deploy_at"] = *deployAt
	}
	if deployJob != "" {
		set["last_deploy_job"] = deployJob
	}
	_, err := s.db.Collection(serversCollection).UpdateOne(ctx, bson.M{"server_id": serverID}, bson.M{"$set": set})
	return err
}

func (s *mongoStore) CreateJob(ctx context.Context, job dbJob) error {
	if strings.TrimSpace(job.JobID) == "" {
		return fmt.Errorf("job_id required")
	}
	now := time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if strings.TrimSpace(job.Status) == "" {
		job.Status = "queued"
	}
	_, err := s.db.Collection(jobsCollection).InsertOne(ctx, job)
	return err
}

func (s *mongoStore) Jobs(ctx context.Context, limit int) ([]dbJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	cur, err := s.db.Collection(jobsCollection).Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []dbJob
	for cur.Next(ctx) {
		var job dbJob
		if err := cur.Decode(&job); err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, cur.Err()
}

func (s *mongoStore) GetJob(ctx context.Context, jobID string) (*dbJob, error) {
	var job dbJob
	err := s.db.Collection(jobsCollection).FindOne(ctx, bson.M{"job_id": jobID}).Decode(&job)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("job not found")
	}
	return &job, err
}

func (s *mongoStore) StartJob(ctx context.Context, jobID string) error {
	now := time.Now().UTC()
	_, err := s.db.Collection(jobsCollection).UpdateOne(ctx, bson.M{"job_id": jobID}, bson.M{
		"$set": bson.M{
			"status":     "running",
			"started_at": now,
		},
	})
	return err
}

func (s *mongoStore) AppendJobLog(ctx context.Context, jobID, message string) error {
	message = strings.TrimRight(message, "\r\n")
	if message == "" {
		return nil
	}
	_, err := s.db.Collection(jobsCollection).UpdateOne(ctx, bson.M{"job_id": jobID}, bson.M{
		"$push": bson.M{"logs": dbJobLog{
			At:      time.Now().UTC(),
			Message: message,
		}},
	})
	return err
}

func (s *mongoStore) FinishJob(ctx context.Context, jobID, status, errText string) error {
	now := time.Now().UTC()
	if status == "" {
		status = "succeeded"
	}
	_, err := s.db.Collection(jobsCollection).UpdateOne(ctx, bson.M{"job_id": jobID}, bson.M{
		"$set": bson.M{
			"status":      status,
			"error":       strings.TrimSpace(errText),
			"finished_at": now,
		},
	})
	return err
}

func (s *mongoStore) SaveEvent(ctx context.Context, event dbEvent) error {
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = newID("evt")
	}
	if strings.TrimSpace(event.Type) == "" {
		return fmt.Errorf("event type required")
	}
	if strings.TrimSpace(event.Severity) == "" {
		event.Severity = "info"
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Collection(eventsCollection).InsertOne(ctx, event)
	return err
}

func (s *mongoStore) Events(ctx context.Context, limit int) ([]dbEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	cur, err := s.db.Collection(eventsCollection).Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []dbEvent
	for cur.Next(ctx) {
		var event dbEvent
		if err := cur.Decode(&event); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, cur.Err()
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
		"failover_policy":        d.FailoverPolicy,
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

func (s *mongoStore) UpdateDomainFailoverState(ctx context.Context, domain string, state domainFailoverState) error {
	_, err := s.db.Collection(domainsCollection).UpdateOne(ctx, bson.M{"domain": domain}, bson.M{
		"$set": bson.M{
			"failover_state": state,
			"updated_at":     time.Now().UTC(),
		},
	})
	return err
}

func (s *mongoStore) SwitchDomainActiveNode(ctx context.Context, domain, nodeID string, state domainFailoverState) error {
	_, err := s.db.Collection(domainsCollection).UpdateOne(ctx, bson.M{"domain": domain}, bson.M{
		"$set": bson.M{
			"active_node_id": nodeID,
			"failover_state": state,
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
