package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	jobTypeSSHTest     = "ssh_test"
	jobTypeDeployNode  = "deploy_node"
	jobTypeRestartNode = "restart_node"
	jobTypeUpgradeNode = "upgrade_node"

	jobStatusQueued    = "queued"
	jobStatusRunning   = "running"
	jobStatusSucceeded = "succeeded"
	jobStatusFailed    = "failed"
)

type serverUpsertPayload struct {
	ServerID         string   `json:"server_id"`
	Name             string   `json:"name"`
	NodeID           string   `json:"node_id"`
	Host             string   `json:"host"`
	SSHPort          int      `json:"ssh_port"`
	SSHUser          string   `json:"ssh_user"`
	AuthType         string   `json:"auth_type"`
	Password         *string  `json:"password"`
	PrivateKey       *string  `json:"private_key"`
	Passphrase       *string  `json:"passphrase"`
	ClearPassword    bool     `json:"clear_password"`
	ClearPrivateKey  bool     `json:"clear_private_key"`
	ClearPassphrase  bool     `json:"clear_passphrase"`
	DeployDir        string   `json:"deploy_dir"`
	Image            string   `json:"image"`
	ProxyPorts       []string `json:"proxy_ports"`
	CertHostPath     string   `json:"cert_host_path"`
	TrafficInterface string   `json:"traffic_iface"`
}

type deployNodePayload struct {
	CentralURL    string   `json:"central_url"`
	NodeToken     string   `json:"node_token"`
	Image         string   `json:"image"`
	DeployDir     string   `json:"deploy_dir"`
	ProxyPorts    []string `json:"proxy_ports"`
	InstallDocker bool     `json:"install_docker"`
	SyncInterval  string   `json:"sync_interval"`
}

type nodeOperationPayload struct {
	Image string `json:"image"`
}

type sshRunner struct {
	client *ssh.Client
}

func (s *adminServer) createSSHTestJob(ctx context.Context, serverID string) (dbJob, error) {
	job := newJob(jobTypeSSHTest, serverID, "", dbJobRequest{})
	if err := s.store.CreateJob(ctx, job); err != nil {
		return dbJob{}, err
	}
	go s.runSSHTestJob(job.JobID, serverID)
	return job, nil
}

func (s *adminServer) createDeployNodeJob(ctx context.Context, serverID string, payload deployNodePayload) (dbJob, error) {
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		return dbJob{}, err
	}
	if strings.TrimSpace(payload.CentralURL) == "" {
		return dbJob{}, fmt.Errorf("central_url required")
	}
	if strings.TrimSpace(payload.NodeToken) == "" {
		return dbJob{}, fmt.Errorf("node_token required")
	}
	if len(strings.TrimSpace(payload.NodeToken)) < 16 {
		return dbJob{}, fmt.Errorf("node_token must be at least 16 characters")
	}
	req := dbJobRequest{
		CentralURL:    strings.TrimSpace(payload.CentralURL),
		Image:         firstNonEmpty(payload.Image, server.Image, "ghcr.io/ferryboatseranade/glider:latest"),
		DeployDir:     firstNonEmpty(payload.DeployDir, server.DeployDir, "/root/data/docker_data/glider"),
		ProxyPorts:    normalizeStringList(append([]string(nil), firstNonEmptySlice(payload.ProxyPorts, server.ProxyPorts)...)),
		InstallDocker: payload.InstallDocker,
		SyncInterval:  firstNonEmpty(payload.SyncInterval, "30s"),
	}
	if len(req.ProxyPorts) == 0 {
		req.ProxyPorts = []string{"443:443", "8443:8443"}
	}
	job := newJob(jobTypeDeployNode, serverID, server.NodeID, req)
	if err := s.store.CreateJob(ctx, job); err != nil {
		return dbJob{}, err
	}
	go s.runDeployNodeJob(job.JobID, serverID, payload.NodeToken)
	return job, nil
}

func (s *adminServer) createNodeOperationJob(ctx context.Context, serverID, jobType string, payload nodeOperationPayload) (dbJob, error) {
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		return dbJob{}, err
	}
	req := dbJobRequest{
		Image:     firstNonEmpty(payload.Image, server.Image),
		DeployDir: firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider"),
	}
	if jobType == jobTypeUpgradeNode && strings.TrimSpace(req.Image) == "" {
		return dbJob{}, fmt.Errorf("image required")
	}
	job := newJob(jobType, serverID, server.NodeID, req)
	if err := s.store.CreateJob(ctx, job); err != nil {
		return dbJob{}, err
	}
	go s.runNodeOperationJob(job.JobID, serverID)
	return job, nil
}

func newJob(jobType, serverID, nodeID string, req dbJobRequest) dbJob {
	return dbJob{
		JobID:     newID("job"),
		Type:      jobType,
		Status:    jobStatusQueued,
		ServerID:  strings.TrimSpace(serverID),
		NodeID:    strings.TrimSpace(nodeID),
		CreatedAt: time.Now().UTC(),
		Request:   req,
	}
}

func newID(prefix string) string {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + base64.RawURLEncoding.EncodeToString(buf)
}

func firstNonEmptySlice(values ...[]string) []string {
	for _, value := range values {
		if len(normalizeStringList(value)) > 0 {
			return value
		}
	}
	return nil
}

func (s *adminServer) runSSHTestJob(jobID, serverID string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	logger.Log("loading server %s", serverID)
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	runner, err := connectSSH(ctx, *server, logger)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, "", "unreachable", err)
		return
	}
	defer runner.Close()
	out, err := runner.Run(ctx, "printf 'glider-ssh-ok '; uname -s; id -un")
	if err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	logger.Log("%s", strings.TrimSpace(out))
	now := time.Now().UTC()
	_ = s.store.UpdateServerStatus(context.Background(), serverID, "ssh_ok", "", &now, nil, "")
	_ = s.store.FinishJob(context.Background(), jobID, jobStatusSucceeded, "")
	s.recordEvent(dbEvent{
		Type:     "server.ssh_test_succeeded",
		Message:  "ssh test succeeded",
		ServerID: serverID,
		NodeID:   server.NodeID,
		JobID:    jobID,
	})
}

func (s *adminServer) runDeployNodeJob(jobID, serverID, nodeToken string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	job, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	runner, err := connectSSH(ctx, *server, logger)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "unreachable", err)
		return
	}
	defer runner.Close()

	req := job.Request
	if req.DeployDir == "" {
		req.DeployDir = firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider")
	}
	if req.Image == "" {
		req.Image = firstNonEmpty(server.Image, "ghcr.io/ferryboatseranade/glider:latest")
	}
	if req.SyncInterval == "" {
		req.SyncInterval = "30s"
	}
	if len(req.ProxyPorts) == 0 {
		req.ProxyPorts = firstNonEmptySlice(server.ProxyPorts, []string{"443:443", "8443:8443"})
	}

	if req.InstallDocker {
		if err := ensureDocker(ctx, runner, logger); err != nil {
			s.finishProvisionJob(jobID, serverID, server.NodeID, "error", err)
			return
		}
	}
	if err := deployNodeOverSSH(ctx, runner, logger, *server, req, nodeToken); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "error", err)
		return
	}
	tokenHash := hashNodeToken(nodeToken)
	if err := s.store.SetNodeTokenHash(context.Background(), server.NodeID, tokenHash); err != nil {
		logger.Log("warning: could not save dedicated node token hash: %v", err)
	}
	now := time.Now().UTC()
	_ = s.store.UpdateServerStatus(context.Background(), serverID, "deployed", "", nil, &now, jobID)
	_ = s.store.FinishJob(context.Background(), jobID, jobStatusSucceeded, "")
	s.recordEvent(dbEvent{
		Type:     "server.deploy_succeeded",
		Message:  "node deploy succeeded",
		ServerID: serverID,
		NodeID:   server.NodeID,
		JobID:    jobID,
		Metadata: map[string]any{"image": req.Image, "deploy_dir": req.DeployDir},
	})
}

func (s *adminServer) runNodeOperationJob(jobID, serverID string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	job, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	runner, err := connectSSH(ctx, *server, logger)
	if err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "unreachable", err)
		return
	}
	defer runner.Close()
	req := job.Request
	if req.DeployDir == "" {
		req.DeployDir = firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider")
	}
	switch job.Type {
	case jobTypeRestartNode:
		err = restartNodeOverSSH(ctx, runner, logger, req.DeployDir)
	case jobTypeUpgradeNode:
		err = upgradeNodeOverSSH(ctx, runner, logger, req.DeployDir, req.Image)
	default:
		err = fmt.Errorf("unsupported node operation %s", job.Type)
	}
	if err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "error", err)
		return
	}
	now := time.Now().UTC()
	status := "restarted"
	eventType := "server.restart_succeeded"
	if job.Type == jobTypeUpgradeNode {
		status = "upgraded"
		eventType = "server.upgrade_succeeded"
		_ = s.store.UpsertServer(context.Background(), dbServer{
			ServerID:     server.ServerID,
			Name:         server.Name,
			NodeID:       server.NodeID,
			Host:         server.Host,
			SSHPort:      server.SSHPort,
			SSHUser:      server.SSHUser,
			AuthType:     server.AuthType,
			DeployDir:    server.DeployDir,
			Image:        req.Image,
			ProxyPorts:   server.ProxyPorts,
			CertHostPath: server.CertHostPath,
			TrafficIface: server.TrafficIface,
			CreatedAt:    server.CreatedAt,
		}, serverSecretUpdate{})
	}
	_ = s.store.UpdateServerStatus(context.Background(), serverID, status, "", nil, &now, jobID)
	_ = s.store.FinishJob(context.Background(), jobID, jobStatusSucceeded, "")
	s.recordEvent(dbEvent{
		Type:     eventType,
		Message:  "node operation succeeded",
		ServerID: serverID,
		NodeID:   server.NodeID,
		JobID:    jobID,
		Metadata: map[string]any{"image": req.Image, "deploy_dir": req.DeployDir},
	})
}

func (s *adminServer) finishProvisionJob(jobID, serverID, nodeID, serverStatus string, err error) {
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	_ = s.store.AppendJobLog(context.Background(), jobID, "error: "+errText)
	_ = s.store.FinishJob(context.Background(), jobID, jobStatusFailed, errText)
	eventType := "job.failed"
	if serverID != "" {
		now := time.Now().UTC()
		var testAt *time.Time
		if serverStatus == "unreachable" {
			testAt = &now
			eventType = "server.ssh_unreachable"
		}
		_ = s.store.UpdateServerStatus(context.Background(), serverID, serverStatus, errText, testAt, nil, "")
	}
	s.recordEvent(dbEvent{
		Type:     eventType,
		Severity: "error",
		Message:  "job failed",
		ServerID: serverID,
		NodeID:   nodeID,
		JobID:    jobID,
		Metadata: map[string]any{"error": errText, "server_status": serverStatus},
	})
	_ = nodeID
}

type jobLogger struct {
	store *mongoStore
	jobID string
}

func (l jobLogger) Log(format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	if l.store != nil && l.jobID != "" {
		_ = l.store.AppendJobLog(context.Background(), l.jobID, msg)
	}
}

func connectSSH(ctx context.Context, server dbServer, logger jobLogger) (*sshRunner, error) {
	if err := normalizeServer(&server); err != nil {
		return nil, err
	}
	auth, err := sshAuthMethods(server)
	if err != nil {
		return nil, err
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("no SSH credentials configured")
	}
	cfg := &ssh.ClientConfig{
		User:            server.SSHUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(server.Host, fmt.Sprintf("%d", server.SSHPort))
	logger.Log("connecting ssh %s@%s", server.SSHUser, addr)
	dialer := net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &sshRunner{client: ssh.NewClient(c, chans, reqs)}, nil
}

func sshAuthMethods(server dbServer) ([]ssh.AuthMethod, error) {
	var out []ssh.AuthMethod
	if strings.TrimSpace(server.PrivateKey) != "" && (server.AuthType == "auto" || server.AuthType == "private_key") {
		var signer ssh.Signer
		var err error
		if strings.TrimSpace(server.Passphrase) != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(server.PrivateKey), []byte(server.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(server.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		out = append(out, ssh.PublicKeys(signer))
	}
	if strings.TrimSpace(server.Password) != "" && (server.AuthType == "auto" || server.AuthType == "password") {
		out = append(out, ssh.Password(server.Password))
	}
	return out, nil
}

func (r *sshRunner) Close() {
	if r != nil && r.client != nil {
		_ = r.client.Close()
	}
}

func (r *sshRunner) Run(ctx context.Context, cmd string) (string, error) {
	session, err := r.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return stdout.String() + stderr.String(), ctx.Err()
	case err := <-done:
		out := stdout.String() + stderr.String()
		if err != nil {
			return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
		}
		return out, nil
	}
}

func (r *sshRunner) WriteFile(ctx context.Context, path, content string, perm string) error {
	quotedPath := shellQuote(path)
	quotedPerm := shellQuote(perm)
	cmd := fmt.Sprintf("umask 077; mkdir -p $(dirname %s); tmp=$(mktemp); cat > \"$tmp\"; chmod %s \"$tmp\"; mv \"$tmp\" %s", quotedPath, quotedPerm, quotedPath)
	session, err := r.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Start(cmd); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(stdin, strings.NewReader(content))
		_ = stdin.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}
}

func ensureDocker(ctx context.Context, runner *sshRunner, logger jobLogger) error {
	out, err := runner.Run(ctx, "command -v docker >/dev/null 2>&1 && docker --version || true")
	if err != nil {
		return err
	}
	if strings.Contains(out, "Docker version") {
		logger.Log("%s", strings.TrimSpace(out))
		return nil
	}
	logger.Log("installing Docker with get.docker.com")
	cmd := "curl -fsSL https://get.docker.com | sh"
	out, err = runner.Run(ctx, cmd)
	logger.Log("%s", strings.TrimSpace(out))
	return err
}

func deployNodeOverSSH(ctx context.Context, runner *sshRunner, logger jobLogger, server dbServer, req dbJobRequest, nodeToken string) error {
	deployDir := firstNonEmpty(req.DeployDir, server.DeployDir, "/root/data/docker_data/glider")
	nodeID := firstNonEmpty(server.NodeID, server.ServerID)
	cacheDir := "/etc/glider-cache"
	certDir := "/etc/glider-certs"
	envContent := renderNodeEnv(nodeID, req.CentralURL, nodeToken, req.SyncInterval, cacheDir, certDir, server.TrafficIface)
	composeContent := renderNodeCompose(req.Image, req.ProxyPorts)
	confContent := renderNodeGliderConf(certDir)

	logger.Log("creating deploy directory %s", deployDir)
	if _, err := runner.Run(ctx, "mkdir -p "+shellQuote(deployDir)+"/rules.d "+shellQuote(deployDir)+"/cache "+shellQuote(deployDir)+"/certs"); err != nil {
		return err
	}
	files := []struct {
		path    string
		content string
		perm    string
	}{
		{deployDir + "/.env", envContent, "600"},
		{deployDir + "/compose.yml", composeContent, "644"},
		{deployDir + "/glider.conf", confContent, "644"},
	}
	for _, file := range files {
		logger.Log("writing %s", file.path)
		if err := runner.WriteFile(ctx, file.path, file.content, file.perm); err != nil {
			return err
		}
	}
	logger.Log("pulling image %s", req.Image)
	cmd := "cd " + shellQuote(deployDir) + " && docker compose pull && docker compose up -d"
	out, err := runner.Run(ctx, cmd)
	if strings.TrimSpace(out) != "" {
		logger.Log("%s", strings.TrimSpace(out))
	}
	if err != nil {
		return err
	}
	out, err = runner.Run(ctx, "cd "+shellQuote(deployDir)+" && docker compose ps")
	if strings.TrimSpace(out) != "" {
		logger.Log("%s", strings.TrimSpace(out))
	}
	return err
}

func restartNodeOverSSH(ctx context.Context, runner *sshRunner, logger jobLogger, deployDir string) error {
	logger.Log("restarting node in %s", deployDir)
	out, err := runner.Run(ctx, "cd "+shellQuote(deployDir)+" && docker compose restart glider-node")
	if strings.TrimSpace(out) != "" {
		logger.Log("%s", strings.TrimSpace(out))
	}
	return err
}

func upgradeNodeOverSSH(ctx context.Context, runner *sshRunner, logger jobLogger, deployDir, image string) error {
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("image required")
	}
	logger.Log("upgrading node in %s to %s", deployDir, image)
	composePath := deployDir + "/compose.yml"
	current, err := runner.Run(ctx, "test -f "+shellQuote(composePath)+" && sed -n '1,200p' "+shellQuote(composePath))
	if err != nil {
		return err
	}
	updated, err := replaceComposeImage(current, image)
	if err != nil {
		return err
	}
	if err := runner.WriteFile(ctx, composePath, updated, "644"); err != nil {
		return err
	}
	out, err := runner.Run(ctx, "cd "+shellQuote(deployDir)+" && docker compose pull && docker compose up -d")
	if strings.TrimSpace(out) != "" {
		logger.Log("%s", strings.TrimSpace(out))
	}
	return err
}

func replaceComposeImage(compose, image string) (string, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", fmt.Errorf("image required")
	}
	lines := strings.Split(compose, "\n")
	replaced := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "image:") {
			prefix := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = prefix + "image: " + image
			replaced = true
			break
		}
	}
	if !replaced {
		return "", fmt.Errorf("compose image line not found")
	}
	return strings.Join(lines, "\n"), nil
}

func renderNodeEnv(nodeID, centralURL, nodeToken, syncInterval, cacheDir, certDir, trafficIface string) string {
	values := map[string]string{
		"GLIDER_MODE":              "node",
		"GLIDER_NODE_ID":           nodeID,
		"GLIDER_CENTRAL_URL":       centralURL,
		"GLIDER_NODE_TOKEN":        nodeToken,
		"GLIDER_SYNC_INTERVAL":     firstNonEmpty(syncInterval, "30s"),
		"GLIDER_CACHE_DIR":         cacheDir,
		"GLIDER_CERT_DIR":          certDir,
		"GLIDER_TRAFFIC_INTERFACE": firstNonEmpty(trafficIface, "eth0"),
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&b, "%s=%s\n", key, shellEnvValue(values[key]))
	}
	return b.String()
}

func renderNodeCompose(image string, proxyPorts []string) string {
	image = firstNonEmpty(image, "ghcr.io/ferryboatseranade/glider:latest")
	proxyPorts = normalizeStringList(proxyPorts)
	if len(proxyPorts) == 0 {
		proxyPorts = []string{"443:443", "8443:8443"}
	}
	var b strings.Builder
	b.WriteString("services:\n")
	b.WriteString("  glider-node:\n")
	fmt.Fprintf(&b, "    image: %s\n", image)
	b.WriteString("    container_name: glider\n")
	b.WriteString("    user: \"0:0\"\n")
	b.WriteString("    ports:\n")
	for _, port := range proxyPorts {
		fmt.Fprintf(&b, "      - %q\n", port)
	}
	b.WriteString("    env_file:\n")
	b.WriteString("      - .env\n")
	b.WriteString("    volumes:\n")
	b.WriteString("      - ./glider.conf:/etc/glider.conf:ro\n")
	b.WriteString("      - ./rules.d:/etc/rules.d\n")
	b.WriteString("      - ./cache:/etc/glider-cache\n")
	b.WriteString("      - ./certs:/etc/glider-certs\n")
	b.WriteString("    command: -config /etc/glider.conf\n")
	b.WriteString("    restart: unless-stopped\n")
	return b.String()
}

func renderNodeGliderConf(certDir string) string {
	certDir = firstNonEmpty(certDir, defaultCertCacheDir)
	return "mode=node\n" +
		"listen=tls://:443?certDir=" + certDir + ",http://\n" +
		"listen=:8443\n" +
		"rules-dir=/etc/rules.d\n"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func shellEnvValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.ContainsAny(value, " \t\r\n#'\"$`\\") {
		return shellQuote(value)
	}
	return value
}

func serverFromPayload(payload serverUpsertPayload) (dbServer, serverSecretUpdate) {
	srv := dbServer{
		ServerID:     payload.ServerID,
		Name:         payload.Name,
		NodeID:       payload.NodeID,
		Host:         payload.Host,
		SSHPort:      payload.SSHPort,
		SSHUser:      payload.SSHUser,
		AuthType:     payload.AuthType,
		DeployDir:    payload.DeployDir,
		Image:        payload.Image,
		ProxyPorts:   payload.ProxyPorts,
		CertHostPath: payload.CertHostPath,
		TrafficIface: payload.TrafficInterface,
	}
	return srv, serverSecretUpdate{
		Password:        payload.Password,
		PrivateKey:      payload.PrivateKey,
		Passphrase:      payload.Passphrase,
		ClearPassword:   payload.ClearPassword,
		ClearPrivateKey: payload.ClearPrivateKey,
		ClearPassphrase: payload.ClearPassphrase,
	}
}

func defaultCentralURL(rHost string) string {
	if value := strings.TrimSpace(os.Getenv("GLIDER_PUBLIC_ADMIN_URL")); value != "" {
		return value
	}
	return ""
}
