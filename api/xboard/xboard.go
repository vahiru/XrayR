package xboard

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
)

// APIClient talks to Xboard's node API. It keeps the legacy XrayR api.API
// surface so Xboard can run under the existing controller while preserving
// Xboard v2 report semantics.
type APIClient struct {
	client *resty.Client

	APIHost     string
	NodeID      int
	MachineID   int
	Key         string
	NodeType    string
	EnableVless bool
	VlessFlow   string
	SpeedLimit  float64
	DeviceLimit int

	LocalRuleList []api.DetectRule

	mu        sync.RWMutex
	node      *nodeConfig
	users     []user
	nodeVer   uint64
	userVer   uint64
	sentNode  uint64
	sentUsers uint64

	configETag string
	userETag   string

	handshakeOnce sync.Once
	handshakeErr  error
	wsStarted     atomic.Bool
	wsStop        func()
	wsMu          sync.RWMutex
	wsWriteCh     chan<- wsMessage
	lastStatus    map[string]interface{}
	lastDevices   map[int][]string
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(strings.TrimRight(apiConfig.APIHost, "/"))

	return &APIClient{
		client:        client,
		APIHost:       strings.TrimRight(apiConfig.APIHost, "/"),
		NodeID:        apiConfig.NodeID,
		MachineID:     apiConfig.MachineID,
		Key:           apiConfig.Key,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: readLocalRuleList(apiConfig.RuleListPath),
		configETag:    "",
		userETag:      "",
	}
}

func readLocalRuleList(path string) []api.DetectRule {
	localRuleList := make([]api.DetectRule, 0)
	if path == "" {
		return localRuleList
	}

	file, err := os.Open(path)
	if err != nil {
		log.Printf("Error when opening file: %s", err)
		return localRuleList
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		localRuleList = append(localRuleList, api.DetectRule{
			ID:      -1,
			Pattern: regexp.MustCompile(fileScanner.Text()),
		})
	}
	if err := fileScanner.Err(); err != nil {
		log.Fatalf("Error while reading file: %s", err)
	}
	return localRuleList
}

func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) Close() error {
	if c.wsStop != nil {
		c.wsStop()
	}
	return nil
}

func (c *APIClient) GetNodeInfo() (*api.NodeInfo, error) {
	c.ensureHandshake()
	if nodeInfo, ok := c.cachedNodeInfo(); ok {
		return nodeInfo, nil
	}

	cfg, err := c.fetchConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New(api.NodeNotModified)
	}
	c.setNode(cfg)

	nodeInfo, err := c.parseNodeInfo(cfg)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.sentNode = c.nodeVer
	c.mu.Unlock()
	return nodeInfo, nil
}

func (c *APIClient) GetUserList() (*[]api.UserInfo, error) {
	if userList, ok := c.cachedUserList(); ok {
		return userList, nil
	}

	users, err := c.fetchUsers()
	if err != nil {
		return nil, err
	}
	if users == nil {
		return nil, errors.New(api.UserNotModified)
	}
	c.setUsers(users)

	userList := c.usersToAPI(users)
	c.mu.Lock()
	c.sentUsers = c.userVer
	c.mu.Unlock()
	return &userList, nil
}

func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	payload := c.nodeStatusPayload(nodeStatus)
	c.sendWS("node.status", c.nodeStatusWSPayload(payload))
	return c.postReport(payload)
}

func (c *APIClient) nodeStatusPayload(nodeStatus *api.NodeStatus) map[string]interface{} {
	vm, _ := mem.VirtualMemory()
	sm, _ := mem.SwapMemory()
	du, _ := disk.Usage("/")
	var memTotal, memUsed, swapTotal, swapUsed, diskTotal, diskUsed uint64
	if vm != nil {
		memTotal, memUsed = vm.Total, vm.Used
	}
	if sm != nil {
		swapTotal, swapUsed = sm.Total, sm.Used
	}
	if du != nil {
		diskTotal, diskUsed = du.Total, du.Used
	}
	payload := map[string]interface{}{
		"status": map[string]interface{}{
			"cpu":  nodeStatus.CPU,
			"mem":  map[string]interface{}{"total": memTotal, "used": memUsed, "percent": nodeStatus.Mem},
			"swap": map[string]interface{}{"total": swapTotal, "used": swapUsed},
			"disk": map[string]interface{}{"total": diskTotal, "used": diskUsed, "percent": nodeStatus.Disk},
		},
		"metrics": map[string]interface{}{
			"uptime": nodeStatus.Uptime,
		},
	}
	c.wsMu.Lock()
	c.lastStatus = cloneAnyMap(payload)
	c.wsMu.Unlock()
	return payload
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUsers *[]api.OnlineUser) error {
	alive := make(map[string][]string)
	online := make(map[string]int)
	devices := make(map[int][]string)
	for _, onlineUser := range *onlineUsers {
		uid := strconv.Itoa(onlineUser.UID)
		alive[uid] = append(alive[uid], onlineUser.IP)
		online[uid] = len(alive[uid])
		devices[onlineUser.UID] = append(devices[onlineUser.UID], onlineUser.IP)
	}
	if len(alive) == 0 {
		return nil
	}
	c.wsMu.Lock()
	c.lastDevices = cloneDeviceMap(devices)
	c.wsMu.Unlock()
	c.sendWS("report.devices", c.deviceReportPayload(devices))
	return c.postReport(map[string]interface{}{
		"alive":  alive,
		"online": online,
	})
}

func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	traffic := make(map[string][2]int64, len(*userTraffic))
	for _, item := range *userTraffic {
		traffic[strconv.Itoa(item.UID)] = [2]int64{item.Upload, item.Download}
	}
	if len(traffic) == 0 {
		return nil
	}
	return c.postReport(map[string]interface{}{"traffic": traffic})
}

func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	c.mu.RLock()
	cfg := c.node
	c.mu.RUnlock()
	if cfg == nil {
		return &c.LocalRuleList, nil
	}

	ruleList := append([]api.DetectRule{}, c.LocalRuleList...)
	for i := range cfg.Routes {
		if cfg.Routes[i].Action == "block" {
			ruleList = append(ruleList, api.DetectRule{
				ID:      cfg.Routes[i].ID,
				Pattern: regexp.MustCompile(strings.Join(cfg.Routes[i].Match, "|")),
			})
			if ruleList[len(ruleList)-1].ID == 0 {
				ruleList[len(ruleList)-1].ID = i
			}
		}
	}
	return &ruleList, nil
}

func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

func (c *APIClient) ensureHandshake() {
	c.handshakeOnce.Do(func() {
		hs, err := c.handshake()
		if err != nil {
			c.handshakeErr = err
			log.Debugf("Xboard handshake failed, REST polling only: %s", err)
			return
		}
		if hs.WebSocket.Enabled && hs.WebSocket.WSURL != "" {
			c.startWS(hs.WebSocket.WSURL)
		}
	})
}

func (c *APIClient) handshake() (*handshakeResponse, error) {
	payload := map[string]interface{}{}
	c.injectAuth(payload)
	res, err := c.client.R().
		SetBody(payload).
		ForceContentType("application/json").
		Post("/api/v2/server/handshake")
	if err != nil {
		return nil, err
	}
	if res.StatusCode() == 404 {
		return nil, fmt.Errorf("handshake endpoint not found")
	}
	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("handshake status %d: %s", res.StatusCode(), res.String())
	}
	var out handshakeResponse
	if err := json.Unmarshal(res.Body(), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *APIClient) fetchConfig() (*nodeConfig, error) {
	path := "/api/v1/server/UniProxy/config"
	if c.MachineID > 0 {
		path = "/api/v2/server/config"
	}
	res, err := c.client.R().
		SetHeader("If-None-Match", c.configETag).
		SetQueryParams(c.authQuery()).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, err
	}
	if res.StatusCode() == 304 {
		return nil, nil
	}
	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("request %s failed: %s", path, res.String())
	}
	if etag := res.Header().Get("Etag"); etag != "" {
		c.configETag = etag
	}

	var cfg nodeConfig
	if err := json.Unmarshal(res.Body(), &cfg); err != nil {
		return nil, err
	}
	if cfg.ServerPort == 0 {
		return nil, errors.New("server port must > 0")
	}
	return &cfg, nil
}

func (c *APIClient) fetchUsers() ([]user, error) {
	path := "/api/v1/server/UniProxy/user"
	if c.MachineID > 0 {
		path = "/api/v2/server/user"
	}
	res, err := c.client.R().
		SetHeader("If-None-Match", c.userETag).
		SetQueryParams(c.authQuery()).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, err
	}
	if res.StatusCode() == 304 {
		return nil, nil
	}
	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("request %s failed: %s", path, res.String())
	}
	if etag := res.Header().Get("Etag"); etag != "" {
		c.userETag = etag
	}

	var out usersResponse
	if err := json.Unmarshal(res.Body(), &out); err != nil {
		return nil, err
	}
	if len(out.Users) == 0 {
		return nil, errors.New("users is null")
	}
	return out.Users, nil
}

func (c *APIClient) postReport(payload map[string]interface{}) error {
	c.injectAuth(payload)
	res, err := c.client.R().
		SetBody(payload).
		ForceContentType("application/json").
		Post("/api/v2/server/report")
	if err == nil && res.StatusCode() < 400 {
		return nil
	}
	if c.MachineID > 0 {
		if err != nil {
			return err
		}
		return fmt.Errorf("report status %d: %s", res.StatusCode(), res.String())
	}
	return c.postLegacyReport(payload)
}

func (c *APIClient) postLegacyReport(payload map[string]interface{}) error {
	if traffic, ok := payload["traffic"]; ok {
		res, err := c.client.R().
			SetQueryParams(c.authQuery()).
			SetBody(traffic).
			ForceContentType("application/json").
			Post("/api/v1/server/UniProxy/push")
		if err != nil {
			return err
		}
		if res.StatusCode() > 399 {
			return fmt.Errorf("legacy traffic report status %d: %s", res.StatusCode(), res.String())
		}
	}
	if alive, ok := payload["alive"]; ok {
		res, err := c.client.R().
			SetQueryParams(c.authQuery()).
			SetBody(alive).
			ForceContentType("application/json").
			Post("/api/v1/server/UniProxy/alive")
		if err != nil {
			return err
		}
		if res.StatusCode() > 399 {
			return fmt.Errorf("legacy alive report status %d: %s", res.StatusCode(), res.String())
		}
	}
	if status, ok := payload["status"]; ok {
		res, err := c.client.R().
			SetQueryParams(c.authQuery()).
			SetBody(status).
			ForceContentType("application/json").
			Post("/api/v1/server/UniProxy/status")
		if err != nil {
			return err
		}
		if res.StatusCode() > 399 {
			return fmt.Errorf("legacy status report status %d: %s", res.StatusCode(), res.String())
		}
	}
	return nil
}

func (c *APIClient) cachedNodeInfo() (*api.NodeInfo, bool) {
	c.mu.RLock()
	cfg := c.node
	changed := cfg != nil && c.nodeVer != c.sentNode
	c.mu.RUnlock()
	if !changed {
		return nil, false
	}
	nodeInfo, err := c.parseNodeInfo(cfg)
	if err != nil {
		log.Printf("parse cached Xboard node failed: %s", err)
		return nil, false
	}
	c.mu.Lock()
	c.sentNode = c.nodeVer
	c.mu.Unlock()
	return nodeInfo, true
}

func (c *APIClient) cachedUserList() (*[]api.UserInfo, bool) {
	c.mu.RLock()
	users := append([]user(nil), c.users...)
	changed := users != nil && c.userVer != c.sentUsers
	c.mu.RUnlock()
	if !changed {
		return nil, false
	}
	userList := c.usersToAPI(users)
	c.mu.Lock()
	c.sentUsers = c.userVer
	c.mu.Unlock()
	return &userList, true
}

func (c *APIClient) setNode(cfg *nodeConfig) {
	c.mu.Lock()
	c.node = cfg
	c.nodeVer++
	c.mu.Unlock()
}

func (c *APIClient) setUsers(users []user) {
	c.mu.Lock()
	c.users = append([]user(nil), users...)
	c.userVer++
	c.mu.Unlock()
}

func (c *APIClient) usersToAPI(users []user) []api.UserInfo {
	userList := make([]api.UserInfo, len(users))
	for i := range users {
		u := api.UserInfo{
			UID:  users[i].ID,
			UUID: users[i].UUID,
		}
		if c.SpeedLimit > 0 {
			u.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			u.SpeedLimit = uint64(users[i].SpeedLimit * 1000000 / 8)
		}
		if c.DeviceLimit > 0 {
			u.DeviceLimit = c.DeviceLimit
		} else {
			u.DeviceLimit = users[i].DeviceLimit
		}
		u.Email = u.UUID + "@xboard.user"
		if normalizeNodeType(c.NodeType, "") == "Shadowsocks" {
			u.Passwd = u.UUID
		}
		userList[i] = u
	}
	return userList
}

func (c *APIClient) parseNodeInfo(cfg *nodeConfig) (*api.NodeInfo, error) {
	nodeType := normalizeNodeType(c.NodeType, cfg.Protocol)
	switch nodeType {
	case "V2ray", "Vmess", "Vless":
		return c.parseV2rayNode(cfg, nodeType)
	case "Trojan":
		return c.parseTrojanNode(cfg, nodeType), nil
	case "Shadowsocks":
		return c.parseSSNode(cfg, nodeType)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeType)
	}
}

func normalizeNodeType(localType, protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vmess":
		return "Vmess"
	case "vless":
		return "Vless"
	case "trojan":
		return "Trojan"
	case "shadowsocks", "ss":
		return "Shadowsocks"
	}
	switch localType {
	case "V2ray", "Vmess", "Vless", "Trojan", "Shadowsocks":
		return localType
	default:
		return strings.Title(strings.ToLower(localType))
	}
}

func (c *APIClient) parseTrojanNode(cfg *nodeConfig, nodeType string) *api.NodeInfo {
	return &api.NodeInfo{
		NodeType:          nodeType,
		NodeID:            c.effectiveNodeID(cfg),
		Port:              uint32(cfg.ServerPort),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              cfg.Host,
		ServiceName:       cfg.ServerName,
		NameServerConfig:  cfg.parseDNSConfig(),
	}
}

func (c *APIClient) parseSSNode(cfg *nodeConfig, nodeType string) (*api.NodeInfo, error) {
	var header json.RawMessage
	if cfg.Plugin == "obfs" || cfg.Obfs == "http" {
		h := simplejson.New()
		h.Set("type", "http")
		h.SetPath([]string{"request", "path"}, "/")
		header, _ = h.Encode()
	}
	return &api.NodeInfo{
		NodeType:          nodeType,
		NodeID:            c.effectiveNodeID(cfg),
		Port:              uint32(cfg.ServerPort),
		TransportProtocol: "tcp",
		CypherMethod:      cfg.Cipher,
		ServerKey:         cfg.ServerKey,
		NameServerConfig:  cfg.parseDNSConfig(),
		Header:            header,
	}, nil
}

func (c *APIClient) parseV2rayNode(cfg *nodeConfig, nodeType string) (*api.NodeInfo, error) {
	var (
		host          string
		header        json.RawMessage
		enableTLS     bool
		enableREALITY bool
	)

	networkSettings := cfg.NetworkSettings
	if networkSettings == nil {
		networkSettings = map[string]interface{}{}
	}
	network := stringFromMap(networkSettings, "network")
	if network == "" {
		network = cfg.Network
	}
	switch cfg.TLS {
	case 1:
		enableTLS = true
	case 2:
		enableTLS = true
		enableREALITY = true
	}

	if headers, ok := networkSettings["headers"]; ok {
		headerBytes, _ := json.Marshal(headers)
		if cfg.Network == "ws" || cfg.Network == "httpupgrade" || cfg.Network == "splithttp" || cfg.Network == "xhttp" {
			js, _ := simplejson.NewJson(headerBytes)
			host = js.Get("Host").MustString()
		}
	}
	if cfg.Network == "tcp" {
		if h, ok := networkSettings["header"]; ok {
			header, _ = json.Marshal(h)
		}
	}
	if mapHost := stringFromMap(networkSettings, "host"); mapHost != "" {
		host = mapHost
	}

	realityConfig := c.realityConfig(cfg)
	return &api.NodeInfo{
		NodeType:            nodeType,
		NodeID:              c.effectiveNodeID(cfg),
		Port:                uint32(cfg.ServerPort),
		AlterID:             0,
		TransportProtocol:   network,
		EnableTLS:           enableTLS,
		Path:                stringFromMap(networkSettings, "path"),
		Host:                host,
		Authority:           stringFromMap(networkSettings, "authority"),
		EnableVless:         c.EnableVless || nodeType == "Vless",
		VlessFlow:           firstNonEmpty(cfg.Flow, c.VlessFlow),
		ServiceName:         stringFromMap(networkSettings, "serviceName"),
		Header:              header,
		EnableREALITY:       enableREALITY,
		REALITYConfig:       realityConfig,
		NameServerConfig:    cfg.parseDNSConfig(),
		AcceptProxyProtocol: cfg.proxyProtocol(),
	}, nil
}

func (c *APIClient) realityConfig(cfg *nodeConfig) *api.REALITYConfig {
	tls := cfg.TLSSettings
	if tls == nil {
		return &api.REALITYConfig{}
	}
	dest := firstNonEmpty(stringFromAny(tls["dest"]), stringFromAny(tls["server_name"]))
	port := stringFromAny(tls["server_port"])
	if port != "" && dest != "" && !strings.Contains(dest, ":") {
		dest += ":" + port
	}
	serverName := stringFromAny(tls["server_name"])
	shortID := stringFromAny(tls["short_id"])
	return &api.REALITYConfig{
		Dest:             dest,
		ProxyProtocolVer: uint64FromAny(tls["xver"]),
		ServerNames:      stringSliceFromAny(tls["server_names"], serverName),
		PrivateKey:       stringFromAny(tls["private_key"]),
		ShortIds:         stringSliceFromAny(tls["short_ids"], shortID),
	}
}

func (c *APIClient) effectiveNodeID(cfg *nodeConfig) int {
	if cfg.NodeID > 0 {
		return cfg.NodeID
	}
	return c.NodeID
}

func (cfg *nodeConfig) proxyProtocol() bool {
	if cfg.AcceptProxy {
		return true
	}
	if cfg.NetworkSettings != nil {
		if v, ok := cfg.NetworkSettings["acceptProxyProtocol"].(bool); ok {
			return v
		}
	}
	return false
}

func (cfg *nodeConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
	for i := range cfg.Routes {
		if cfg.Routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(cfg.Routes[i].ActionValue)},
				Domains: cfg.Routes[i].Match,
			})
		}
	}
	return
}

func (c *APIClient) injectAuth(payload map[string]interface{}) {
	payload["token"] = c.Key
	if c.MachineID > 0 {
		payload["machine_id"] = c.MachineID
		if c.NodeID > 0 {
			payload["node_id"] = c.NodeID
		}
		return
	}
	payload["node_id"] = c.NodeID
	nodeType := strings.ToLower(c.NodeType)
	if c.NodeType == "V2ray" && c.EnableVless {
		nodeType = "vless"
	}
	if nodeType != "" {
		payload["node_type"] = nodeType
	}
}

func (c *APIClient) authQuery() map[string]string {
	q := map[string]string{"token": c.Key}
	if c.MachineID > 0 {
		q["machine_id"] = strconv.Itoa(c.MachineID)
		if c.NodeID > 0 {
			q["node_id"] = strconv.Itoa(c.NodeID)
		}
		return q
	}
	q["node_id"] = strconv.Itoa(c.NodeID)
	nodeType := strings.ToLower(c.NodeType)
	if c.NodeType == "V2ray" && c.EnableVless {
		nodeType = "vless"
	}
	if nodeType != "" {
		q["node_type"] = nodeType
	}
	return q
}

func stringFromMap(m map[string]interface{}, key string) string {
	return stringFromAny(m[key])
}

func stringFromAny(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func uint64FromAny(v interface{}) uint64 {
	switch t := v.(type) {
	case uint64:
		return t
	case int:
		return uint64(t)
	case int64:
		return uint64(t)
	case float64:
		return uint64(t)
	case string:
		n, _ := strconv.ParseUint(t, 10, 64)
		return n
	default:
		return 0
	}
}

func stringSliceFromAny(v interface{}, fallback string) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s := stringFromAny(item); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	case string:
		if t != "" {
			return []string{t}
		}
	}
	if fallback == "" {
		return nil
	}
	return []string{fallback}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
