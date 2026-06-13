package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	jobTypeSSHTest      = "ssh_test"
	jobTypePreflight    = "preflight_node"
	jobTypeInspectNode  = "inspect_node"
	jobTypeDeployNode   = "deploy_node"
	jobTypeOnboardNode  = "onboard_node"
	jobTypeRestartNode  = "restart_node"
	jobTypeUpgradeNode  = "upgrade_node"
	jobTypeRollbackNode = "rollback_node"

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
	CentralURL           string   `json:"central_url"`
	NodeToken            string   `json:"node_token"`
	Image                string   `json:"image"`
	DeployDir            string   `json:"deploy_dir"`
	ProxyPorts           []string `json:"proxy_ports"`
	InstallDocker        bool     `json:"install_docker"`
	SyncInterval         string   `json:"sync_interval"`
	WaitHeartbeatSeconds int      `json:"wait_heartbeat_seconds"`
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

func (s *adminServer) createPreflightNodeJob(ctx context.Context, serverID string) (dbJob, error) {
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		return dbJob{}, err
	}
	req := dbJobRequest{
		Image:      firstNonEmpty(server.Image, "ghcr.io/ferryboatseranade/glider:latest"),
		DeployDir:  firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider"),
		ProxyPorts: normalizeStringList(firstNonEmptySlice(server.ProxyPorts, []string{"443:443", "8443:8443"})),
	}
	job := newJob(jobTypePreflight, serverID, server.NodeID, req)
	if err := s.store.CreateJob(ctx, job); err != nil {
		return dbJob{}, err
	}
	go s.runPreflightNodeJob(job.JobID, serverID)
	return job, nil
}

func (s *adminServer) createInspectNodeJob(ctx context.Context, serverID string) (dbJob, error) {
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		return dbJob{}, err
	}
	req := dbJobRequest{
		Image:      firstNonEmpty(server.Image, "ghcr.io/ferryboatseranade/glider:latest"),
		DeployDir:  firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider"),
		ProxyPorts: normalizeStringList(firstNonEmptySlice(server.ProxyPorts, []string{"443:443", "8443:8443"})),
	}
	job := newJob(jobTypeInspectNode, serverID, server.NodeID, req)
	if err := s.store.CreateJob(ctx, job); err != nil {
		return dbJob{}, err
	}
	go s.runInspectNodeJob(job.JobID, serverID)
	return job, nil
}

func (s *adminServer) createDeployNodeJob(ctx context.Context, serverID string, payload deployNodePayload) (dbJob, error) {
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		return dbJob{}, err
	}
	centralURL := firstNonEmpty(payload.CentralURL, defaultCentralURL(nil))
	if strings.TrimSpace(centralURL) == "" {
		return dbJob{}, fmt.Errorf("central_url required")
	}
	if strings.TrimSpace(payload.NodeToken) == "" {
		return dbJob{}, fmt.Errorf("node_token required")
	}
	if len(strings.TrimSpace(payload.NodeToken)) < 16 {
		return dbJob{}, fmt.Errorf("node_token must be at least 16 characters")
	}
	req := dbJobRequest{
		CentralURL:           strings.TrimSpace(centralURL),
		Image:                firstNonEmpty(payload.Image, server.Image, "ghcr.io/ferryboatseranade/glider:latest"),
		DeployDir:            firstNonEmpty(payload.DeployDir, server.DeployDir, "/root/data/docker_data/glider"),
		ProxyPorts:           normalizeStringList(append([]string(nil), firstNonEmptySlice(payload.ProxyPorts, server.ProxyPorts)...)),
		InstallDocker:        payload.InstallDocker,
		SyncInterval:         firstNonEmpty(payload.SyncInterval, "30s"),
		WaitHeartbeatSeconds: payload.WaitHeartbeatSeconds,
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

func (s *adminServer) createOnboardNodeJob(ctx context.Context, serverID string, payload deployNodePayload) (dbJob, error) {
	server, err := s.store.GetServer(ctx, serverID)
	if err != nil {
		return dbJob{}, err
	}
	centralURL := firstNonEmpty(payload.CentralURL, defaultCentralURL(nil))
	if strings.TrimSpace(centralURL) == "" {
		return dbJob{}, fmt.Errorf("central_url required")
	}
	req := dbJobRequest{
		CentralURL:           strings.TrimSpace(centralURL),
		Image:                firstNonEmpty(payload.Image, server.Image, "ghcr.io/ferryboatseranade/glider:latest"),
		DeployDir:            firstNonEmpty(payload.DeployDir, server.DeployDir, "/root/data/docker_data/glider"),
		ProxyPorts:           normalizeStringList(append([]string(nil), firstNonEmptySlice(payload.ProxyPorts, server.ProxyPorts)...)),
		InstallDocker:        payload.InstallDocker,
		SyncInterval:         firstNonEmpty(payload.SyncInterval, "30s"),
		WaitHeartbeatSeconds: payload.WaitHeartbeatSeconds,
	}
	if len(req.ProxyPorts) == 0 {
		req.ProxyPorts = []string{"443:443", "8443:8443"}
	}
	if req.WaitHeartbeatSeconds <= 0 {
		req.WaitHeartbeatSeconds = 120
	}
	job := newJob(jobTypeOnboardNode, serverID, server.NodeID, req)
	if err := s.store.CreateJob(ctx, job); err != nil {
		return dbJob{}, err
	}
	go s.runOnboardNodeJob(job.JobID, serverID)
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
	if jobType == jobTypeRollbackNode {
		req.Image = strings.TrimSpace(server.PreviousImage)
		if req.Image == "" {
			return dbJob{}, fmt.Errorf("previous_image required")
		}
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
	var server *dbServer
	if err := logger.Step("load-server", fmt.Sprintf("load server %s", serverID), func() error {
		var err error
		server, err = s.store.GetServer(ctx, serverID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var runner *sshRunner
	if err := logger.Step("ssh-connect", "connect to server over SSH", func() error {
		var err error
		runner, err = connectSSH(ctx, *server, logger)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "unreachable", err)
		return
	}
	defer runner.Close()
	var out string
	if err := logger.Step("ssh-smoke-test", "run SSH smoke command", func() error {
		var err error
		out, err = runner.Run(ctx, "printf 'glider-ssh-ok '; uname -s; id -un")
		return err
	}); err != nil {
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

func (s *adminServer) runInspectNodeJob(jobID, serverID string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	var job *dbJob
	if err := logger.Step("load-job", "load inspect job", func() error {
		var err error
		job, err = s.store.GetJob(ctx, jobID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var server *dbServer
	if err := logger.Step("load-server", fmt.Sprintf("load server %s", serverID), func() error {
		var err error
		server, err = s.store.GetServer(ctx, serverID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var runner *sshRunner
	if err := logger.Step("ssh-connect", "connect to server over SSH", func() error {
		var err error
		runner, err = connectSSH(ctx, *server, logger)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "unreachable", err)
		return
	}
	defer runner.Close()
	req := job.Request
	if req.DeployDir == "" {
		req.DeployDir = firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider")
	}
	if len(req.ProxyPorts) == 0 {
		req.ProxyPorts = firstNonEmptySlice(server.ProxyPorts, []string{"443:443", "8443:8443"})
	}
	var runtime serverRuntimeSnapshot
	if err := logger.Step("inspect-node", "inspect remote node runtime", func() error {
		var err error
		runtime, err = inspectNodeOverSSH(ctx, runner, logger, *server, req)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "inspect_failed", err)
		return
	}
	status := "inspect_ok"
	if runtime.ContainerStatus == "" || runtime.ContainerStatus == "missing" {
		status = "container_missing"
	} else if runtime.ContainerStatus != "running" {
		status = "container_" + strings.ReplaceAll(runtime.ContainerStatus, " ", "_")
	}
	_ = s.store.UpdateServerRuntime(context.Background(), serverID, runtime, status, "", jobID)
	_ = s.store.FinishJob(context.Background(), jobID, jobStatusSucceeded, "")
	s.recordEvent(dbEvent{
		Type:     "server.inspect_succeeded",
		Message:  "node runtime inspected",
		ServerID: serverID,
		NodeID:   server.NodeID,
		JobID:    jobID,
		Metadata: map[string]any{
			"deploy_dir":       runtime.DeployDir,
			"container_status": runtime.ContainerStatus,
			"compose_image":    runtime.ComposeImage,
			"runtime_node_id":  runtime.RuntimeNodeID,
		},
	})
}

func (s *adminServer) runPreflightNodeJob(jobID, serverID string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	var job *dbJob
	if err := logger.Step("load-job", "load provisioning job", func() error {
		var err error
		job, err = s.store.GetJob(ctx, jobID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var server *dbServer
	if err := logger.Step("load-server", fmt.Sprintf("load server %s", serverID), func() error {
		var err error
		server, err = s.store.GetServer(ctx, serverID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var runner *sshRunner
	if err := logger.Step("ssh-connect", "connect to server over SSH", func() error {
		var err error
		runner, err = connectSSH(ctx, *server, logger)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "unreachable", err)
		return
	}
	defer runner.Close()
	req := job.Request
	if req.DeployDir == "" {
		req.DeployDir = firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider")
	}
	if len(req.ProxyPorts) == 0 {
		req.ProxyPorts = firstNonEmptySlice(server.ProxyPorts, []string{"443:443", "8443:8443"})
	}
	if err := logger.Step("preflight-node", "inspect remote node prerequisites", func() error {
		return preflightNodeOverSSH(ctx, runner, logger, *server, req)
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "preflight_failed", err)
		return
	}
	now := time.Now().UTC()
	_ = s.store.UpdateServerStatus(context.Background(), serverID, "preflight_ok", "", &now, nil, jobID)
	_ = s.store.FinishJob(context.Background(), jobID, jobStatusSucceeded, "")
	s.recordEvent(dbEvent{
		Type:     "server.preflight_succeeded",
		Message:  "node preflight succeeded",
		ServerID: serverID,
		NodeID:   server.NodeID,
		JobID:    jobID,
		Metadata: map[string]any{"deploy_dir": req.DeployDir, "image": req.Image, "proxy_ports": req.ProxyPorts},
	})
}

func (s *adminServer) runDeployNodeJob(jobID, serverID, nodeToken string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	var job *dbJob
	if err := logger.Step("load-job", "load deployment job", func() error {
		var err error
		job, err = s.store.GetJob(ctx, jobID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var server *dbServer
	if err := logger.Step("load-server", fmt.Sprintf("load server %s", serverID), func() error {
		var err error
		server, err = s.store.GetServer(ctx, serverID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var runner *sshRunner
	if err := logger.Step("ssh-connect", "connect to server over SSH", func() error {
		var err error
		runner, err = connectSSH(ctx, *server, logger)
		return err
	}); err != nil {
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
		if err := logger.Step("ensure-docker", "ensure Docker and Compose are available", func() error {
			return ensureDocker(ctx, runner, logger)
		}); err != nil {
			s.finishProvisionJob(jobID, serverID, server.NodeID, "error", err)
			return
		}
	}
	if err := deployNodeOverSSH(ctx, runner, logger, *server, req, nodeToken, func() error {
		tokenHash := hashNodeToken(nodeToken)
		if err := s.store.SetNodeTokenHash(context.Background(), server.NodeID, tokenHash); err != nil {
			return fmt.Errorf("save dedicated node token hash: %w", err)
		}
		logger.Log("dedicated token hash saved for node %s", server.NodeID)
		return nil
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "error", err)
		return
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

func (s *adminServer) runOnboardNodeJob(jobID, serverID string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	var job *dbJob
	if err := logger.Step("load-job", "load onboarding job", func() error {
		var err error
		job, err = s.store.GetJob(ctx, jobID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var server *dbServer
	if err := logger.Step("load-server", fmt.Sprintf("load server %s", serverID), func() error {
		var err error
		server, err = s.store.GetServer(ctx, serverID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var runner *sshRunner
	if err := logger.Step("ssh-connect", "connect to server over SSH", func() error {
		var err error
		runner, err = connectSSH(ctx, *server, logger)
		return err
	}); err != nil {
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
	if req.WaitHeartbeatSeconds <= 0 {
		req.WaitHeartbeatSeconds = 120
	}

	logger.Log("starting node onboarding for %s", server.NodeID)
	if err := logger.Step("preflight-node", "inspect remote node prerequisites", func() error {
		return preflightNodeOverSSH(ctx, runner, logger, *server, req)
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "preflight_failed", err)
		return
	}
	if req.InstallDocker {
		if err := logger.Step("ensure-docker", "ensure Docker and Compose are available", func() error {
			return ensureDocker(ctx, runner, logger)
		}); err != nil {
			s.finishProvisionJob(jobID, serverID, server.NodeID, "error", err)
			return
		}
	}
	nodeToken := generateNodeToken()
	if err := deployNodeOverSSH(ctx, runner, logger, *server, req, nodeToken, func() error {
		if err := s.store.SetNodeTokenHash(context.Background(), server.NodeID, hashNodeToken(nodeToken)); err != nil {
			return fmt.Errorf("save dedicated node token hash: %w", err)
		}
		logger.Log("dedicated token generated and saved for node %s", server.NodeID)
		return nil
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "error", err)
		return
	}
	if err := logger.Step("wait-heartbeat", "wait for fresh node heartbeat", func() error {
		return s.waitForNodeHeartbeat(ctx, logger, server.NodeID, time.Duration(req.WaitHeartbeatSeconds)*time.Second)
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "heartbeat_pending", err)
		return
	}
	now := time.Now().UTC()
	_ = s.store.UpdateServerStatus(context.Background(), serverID, "onboarded", "", &now, &now, jobID)
	_ = s.store.FinishJob(context.Background(), jobID, jobStatusSucceeded, "")
	s.recordEvent(dbEvent{
		Type:     "server.onboard_succeeded",
		Message:  "node onboarding succeeded",
		ServerID: serverID,
		NodeID:   server.NodeID,
		JobID:    jobID,
		Metadata: map[string]any{"image": req.Image, "deploy_dir": req.DeployDir, "central_url": req.CentralURL},
	})
}

func (s *adminServer) runNodeOperationJob(jobID, serverID string) {
	ctx := context.Background()
	_ = s.store.StartJob(ctx, jobID)
	logger := jobLogger{store: s.store, jobID: jobID}
	var job *dbJob
	if err := logger.Step("load-job", "load node operation job", func() error {
		var err error
		job, err = s.store.GetJob(ctx, jobID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var server *dbServer
	if err := logger.Step("load-server", fmt.Sprintf("load server %s", serverID), func() error {
		var err error
		server, err = s.store.GetServer(ctx, serverID)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, "", "error", err)
		return
	}
	var runner *sshRunner
	if err := logger.Step("ssh-connect", "connect to server over SSH", func() error {
		var err error
		runner, err = connectSSH(ctx, *server, logger)
		return err
	}); err != nil {
		s.finishProvisionJob(jobID, serverID, server.NodeID, "unreachable", err)
		return
	}
	defer runner.Close()
	req := job.Request
	if req.DeployDir == "" {
		req.DeployDir = firstNonEmpty(server.DeployDir, "/root/data/docker_data/glider")
	}
	var err error
	switch job.Type {
	case jobTypeRestartNode:
		err = logger.Step("restart-node", "restart remote node container", func() error {
			return restartNodeOverSSH(ctx, runner, logger, req.DeployDir)
		})
	case jobTypeUpgradeNode:
		err = logger.Step("upgrade-node", "pull new image and recreate remote node", func() error {
			return upgradeNodeOverSSH(ctx, runner, logger, req.DeployDir, req.Image)
		})
	case jobTypeRollbackNode:
		err = logger.Step("rollback-node", "restore previous image and recreate remote node", func() error {
			return upgradeNodeOverSSH(ctx, runner, logger, req.DeployDir, req.Image)
		})
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
		_ = s.store.UpdateServerImages(context.Background(), serverID, req.Image, server.Image)
	}
	if job.Type == jobTypeRollbackNode {
		status = "rolled_back"
		eventType = "server.rollback_succeeded"
		_ = s.store.UpdateServerImages(context.Background(), serverID, req.Image, server.Image)
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

func (l jobLogger) Step(name, message string, fn func() error) error {
	name = strings.TrimSpace(name)
	if message == "" {
		message = name
	}
	l.Log("step %s started: %s", name, message)
	if l.store != nil && l.jobID != "" {
		_ = l.store.StartJobStep(context.Background(), l.jobID, name, message)
	}
	err := fn()
	status := jobStatusSucceeded
	errText := ""
	if err != nil {
		status = jobStatusFailed
		errText = err.Error()
	}
	if l.store != nil && l.jobID != "" {
		_ = l.store.FinishJobStep(context.Background(), l.jobID, name, status, errText)
	}
	if err != nil {
		l.Log("step %s failed: %s", name, errText)
		return err
	}
	l.Log("step %s succeeded", name)
	return nil
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

func preflightNodeOverSSH(ctx context.Context, runner *sshRunner, logger jobLogger, server dbServer, req dbJobRequest) error {
	deployDir := firstNonEmpty(req.DeployDir, server.DeployDir, "/root/data/docker_data/glider")
	logger.Log("preflight deploy directory %s", deployDir)
	checks := []string{
		"printf 'host '; hostname || true",
		"printf 'user '; id -un",
		"printf 'kernel '; uname -sr",
		"printf 'docker '; docker --version 2>/dev/null || printf 'missing'",
		"printf 'compose '; docker compose version 2>/dev/null || printf 'missing'",
		"printf 'deploy_dir '; if test -d " + shellQuote(deployDir) + "; then printf 'exists'; else printf 'missing'; fi",
		"printf 'compose_file '; if test -f " + shellQuote(deployDir+"/compose.yml") + "; then printf 'exists'; else printf 'missing'; fi",
		"printf 'container '; docker inspect glider --format '{{.Config.Image}} {{.State.Status}}' 2>/dev/null || printf 'missing'",
		"printf 'disk '; df -h " + shellQuote(deployDir) + " 2>/dev/null | tail -n 1 || df -h / | tail -n 1",
		"printf 'memory '; free -m 2>/dev/null | awk 'NR==2{print $2\"MB total, \"$7\"MB available\"}' || true",
	}
	for _, cmd := range checks {
		out, err := runner.Run(ctx, cmd)
		if strings.TrimSpace(out) != "" {
			logger.Log("%s", strings.TrimSpace(out))
		}
		if err != nil {
			return err
		}
	}
	for _, mapping := range normalizeStringList(req.ProxyPorts) {
		hostPort := hostPortFromMapping(mapping)
		if hostPort == "" {
			logger.Log("port %s skipped: could not parse host port", mapping)
			continue
		}
		cmd := fmt.Sprintf("printf 'port %s '; if (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || true) | awk '{print $4}' | grep -Eq '(^|:|\\])%s$'; then printf 'listening'; else printf 'free'; fi", hostPort, hostPort)
		out, err := runner.Run(ctx, cmd)
		if strings.TrimSpace(out) != "" {
			logger.Log("%s", strings.TrimSpace(out))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func inspectNodeOverSSH(ctx context.Context, runner *sshRunner, logger jobLogger, server dbServer, req dbJobRequest) (serverRuntimeSnapshot, error) {
	deployDir := firstNonEmpty(req.DeployDir, server.DeployDir, "/root/data/docker_data/glider")
	now := time.Now().UTC()
	snap := serverRuntimeSnapshot{
		InspectedAt: &now,
		DeployDir:   deployDir,
	}
	cmd := strings.Join([]string{
		"set +e",
		"printf 'hostname=%s\\n' \"$(hostname 2>/dev/null)\"",
		"printf 'ssh_user=%s\\n' \"$(id -un 2>/dev/null)\"",
		"printf 'kernel=%s\\n' \"$(uname -sr 2>/dev/null)\"",
		"printf 'docker_version=%s\\n' \"$(docker --version 2>/dev/null || printf missing)\"",
		"printf 'compose_version=%s\\n' \"$(docker compose version 2>/dev/null || printf missing)\"",
		"if test -d " + shellQuote(deployDir) + "; then printf 'deploy_dir_exists=true\\n'; else printf 'deploy_dir_exists=false\\n'; fi",
		"if test -f " + shellQuote(deployDir+"/compose.yml") + "; then printf 'compose_file_exists=true\\n'; else printf 'compose_file_exists=false\\n'; fi",
		"if test -f " + shellQuote(deployDir+"/compose.yml") + "; then awk 'BEGIN{found=0} /^[[:space:]]*image:[[:space:]]*/ && found==0 {sub(/^[[:space:]]*image:[[:space:]]*/, \"\"); print \"compose_image=\"$0; found=1}' " + shellQuote(deployDir+"/compose.yml") + "; fi",
		"docker inspect glider --format 'container_image={{.Config.Image}}' 2>/dev/null || printf 'container_image=missing\\n'",
		"docker inspect glider --format 'container_status={{.State.Status}}' 2>/dev/null || printf 'container_status=missing\\n'",
		"docker inspect glider --format 'container_started={{.State.StartedAt}}' 2>/dev/null || printf 'container_started=\\n'",
		"docker port glider 2>/dev/null | tr '\\n' ';' | sed 's/^/container_ports=/; s/;$//'",
		"if test -f " + shellQuote(deployDir+"/.env") + "; then awk -F= '/^GLIDER_(MODE|NODE_ID|CENTRAL_URL|SYNC_INTERVAL|TRAFFIC_INTERFACE|CACHE_DIR|CERT_DIR)=/ {print $1\"=\"$2}' " + shellQuote(deployDir+"/.env") + "; fi",
		"if test -f " + shellQuote(deployDir+"/glider.conf") + "; then awk -F= '/^[[:space:]]*mode[[:space:]]*=/ {gsub(/[[:space:]]/, \"\", $1); sub(/^[[:space:]]*/, \"\", $2); print \"CONFIG_MODE=\"$2; exit}' " + shellQuote(deployDir+"/glider.conf") + "; fi",
		"printf 'disk=%s\\n' \"$(df -h " + shellQuote(deployDir) + " 2>/dev/null | tail -n 1 || df -h / 2>/dev/null | tail -n 1)\"",
		"printf 'memory=%s\\n' \"$(free -m 2>/dev/null | awk 'NR==2{print $2\"MB total, \"$7\"MB available\"}')\"",
	}, "\n")
	out, err := runner.Run(ctx, cmd)
	if strings.TrimSpace(out) != "" {
		logger.Log("%s", sanitizeInspectLog(out))
	}
	if err != nil {
		return snap, err
	}
	values := parseKeyValueLines(out)
	snap.Hostname = values["hostname"]
	snap.SSHUser = values["ssh_user"]
	snap.Kernel = values["kernel"]
	snap.DockerVersion = values["docker_version"]
	snap.ComposeVersion = values["compose_version"]
	snap.DeployDirExists = parseBoolString(values["deploy_dir_exists"])
	snap.ComposeFileExists = parseBoolString(values["compose_file_exists"])
	snap.ComposeImage = values["compose_image"]
	snap.ContainerImage = values["container_image"]
	snap.ContainerStatus = values["container_status"]
	snap.ContainerStarted = values["container_started"]
	snap.ContainerPorts = values["container_ports"]
	snap.Mode = values["GLIDER_MODE"]
	if snap.Mode == "" {
		snap.Mode = values["CONFIG_MODE"]
	}
	snap.RuntimeNodeID = values["GLIDER_NODE_ID"]
	snap.CentralURL = values["GLIDER_CENTRAL_URL"]
	snap.SyncInterval = values["GLIDER_SYNC_INTERVAL"]
	snap.TrafficIface = values["GLIDER_TRAFFIC_INTERFACE"]
	snap.CacheDir = values["GLIDER_CACHE_DIR"]
	snap.CertDir = values["GLIDER_CERT_DIR"]
	snap.Disk = values["disk"]
	snap.Memory = values["memory"]
	for _, mapping := range normalizeStringList(req.ProxyPorts) {
		port := hostPortFromMapping(mapping)
		if port == "" {
			continue
		}
		status := inspectPortStatus(ctx, runner, port)
		snap.PortStatus = append(snap.PortStatus, serverPortStatus{Port: port, Status: status})
		logger.Log("port %s %s", port, status)
	}
	if snap.ContainerStatus == "" {
		snap.ContainerStatus = "unknown"
	}
	return snap, nil
}

func inspectPortStatus(ctx context.Context, runner *sshRunner, port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return "unknown"
	}
	cmd := fmt.Sprintf("if (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || true) | awk '{print $4}' | grep -Eq '(^|:|\\])%s$'; then printf listening; else printf free; fi", port)
	out, err := runner.Run(ctx, cmd)
	if err != nil {
		return "unknown"
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return "unknown"
	}
	return out
}

func parseKeyValueLines(out string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := ""
		if len(parts) > 1 {
			value = strings.TrimSpace(parts[1])
		}
		if key != "" {
			values[key] = value
		}
	}
	return values
}

func parseBoolString(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}

func sanitizeInspectLog(out string) string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "GLIDER_NODE_TOKEN=") {
			continue
		}
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func hostPortFromMapping(mapping string) string {
	mapping = strings.TrimSpace(strings.Trim(mapping, `"'`))
	if mapping == "" {
		return ""
	}
	if strings.Contains(mapping, "/") {
		mapping = strings.SplitN(mapping, "/", 2)[0]
	}
	parts := strings.Split(mapping, ":")
	candidates := []string{mapping}
	if len(parts) >= 2 {
		candidates = append(candidates, parts[len(parts)-2])
	}
	if len(parts) == 1 {
		candidates = append(candidates, parts[0])
	}
	for _, part := range candidates {
		part = strings.Trim(part, "[] ")
		if _, err := strconv.Atoi(part); err == nil {
			return part
		}
	}
	return ""
}

func deployNodeOverSSH(ctx context.Context, runner *sshRunner, logger jobLogger, server dbServer, req dbJobRequest, nodeToken string, beforeStart func() error) error {
	deployDir := firstNonEmpty(req.DeployDir, server.DeployDir, "/root/data/docker_data/glider")
	nodeID := firstNonEmpty(server.NodeID, server.ServerID)
	cacheDir := "/etc/glider-cache"
	certDir := "/etc/glider-certs"
	envContent := renderNodeEnv(nodeID, req.CentralURL, nodeToken, req.SyncInterval, cacheDir, certDir, server.TrafficIface)
	composeContent := renderNodeCompose(req.Image, req.ProxyPorts)
	confContent := renderNodeGliderConf(certDir)

	logger.Log("creating deploy directory %s", deployDir)
	if err := logger.Step("prepare-deploy-dir", "create node deployment directories", func() error {
		_, err := runner.Run(ctx, "mkdir -p "+shellQuote(deployDir)+"/rules.d "+shellQuote(deployDir)+"/cache "+shellQuote(deployDir)+"/certs")
		return err
	}); err != nil {
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
	if err := logger.Step("write-node-files", "write node .env, compose, and config", func() error {
		for _, file := range files {
			logger.Log("writing %s", file.path)
			if err := runner.WriteFile(ctx, file.path, file.content, file.perm); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	logger.Log("pulling image %s", req.Image)
	var out string
	if err := logger.Step("pull-image", fmt.Sprintf("pull image %s", req.Image), func() error {
		pullCmd := "cd " + shellQuote(deployDir) + " && docker compose pull"
		var err error
		out, err = runner.Run(ctx, pullCmd)
		if strings.TrimSpace(out) != "" {
			logger.Log("%s", strings.TrimSpace(out))
		}
		return err
	}); err != nil {
		return err
	}
	if beforeStart != nil {
		if err := logger.Step("save-node-token", "save dedicated node token hash before start", beforeStart); err != nil {
			return err
		}
	}
	if err := logger.Step("start-node", "start node container", func() error {
		cmd := "cd " + shellQuote(deployDir) + " && docker compose up -d"
		var err error
		out, err = runner.Run(ctx, cmd)
		if strings.TrimSpace(out) != "" {
			logger.Log("%s", strings.TrimSpace(out))
		}
		return err
	}); err != nil {
		return err
	}
	return logger.Step("verify-node-container", "inspect node container state", func() error {
		out, err := runner.Run(ctx, "cd "+shellQuote(deployDir)+" && docker compose ps")
		if strings.TrimSpace(out) != "" {
			logger.Log("%s", strings.TrimSpace(out))
		}
		return err
	})
}

func (s *adminServer) waitForNodeHeartbeat(ctx context.Context, logger jobLogger, nodeID string, timeout time.Duration) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return fmt.Errorf("node_id required")
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	deadline := time.Now().UTC().Add(timeout)
	logger.Log("waiting up to %s for node %s heartbeat", timeout.Round(time.Second), nodeID)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		cctx, cancel := withTimeout(ctx)
		node, err := s.store.GetNode(cctx, nodeID)
		cancel()
		if err == nil && nodeHeartbeatFresh(*node, time.Now().UTC()) {
			logger.Log("node %s heartbeat received from %s with config %s", nodeID, firstNonEmpty(node.PublicIP, node.Hostname, "-"), shortLogVersion(node.ConfigVersion))
			return nil
		}
		if time.Now().UTC().After(deadline) {
			if err != nil {
				return fmt.Errorf("node heartbeat not received before timeout: %w", err)
			}
			return fmt.Errorf("node heartbeat not healthy before timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func generateNodeToken() string {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	return "node-" + base64.RawURLEncoding.EncodeToString(buf)
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

func defaultCentralURL(r *http.Request) string {
	if value := strings.TrimSpace(os.Getenv("GLIDER_PUBLIC_ADMIN_URL")); value != "" {
		return value
	}
	if r != nil && strings.TrimSpace(r.Host) != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
		return scheme + "://" + strings.TrimSpace(r.Host)
	}
	return ""
}

func shortLogVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	if len(value) > 12 {
		return value[:12]
	}
	return value
}
