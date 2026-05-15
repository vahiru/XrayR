package xboard

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	wsEventSyncConfig    = "sync.config"
	wsEventSyncUsers     = "sync.users"
	wsEventSyncUserDelta = "sync.user.delta"
	wsEventSyncDevices   = "sync.devices"
	wsEventReportDevices = "report.devices"
)

type wsMessage struct {
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data,omitempty"`
	Timestamp int64           `json:"timestamp,omitempty"`
}

type syncConfigPayload struct {
	Config    nodeConfig `json:"config"`
	Timestamp int64      `json:"timestamp"`
	NodeID    int        `json:"node_id"`
}

type syncUsersPayload struct {
	Users     []user `json:"users"`
	Timestamp int64  `json:"timestamp"`
	NodeID    int    `json:"node_id"`
}

type syncUserDeltaPayload struct {
	Action    string `json:"action"`
	Users     []user `json:"users"`
	Timestamp int64  `json:"timestamp"`
	NodeID    int    `json:"node_id"`
}

type syncDevicesPayload struct {
	Users     map[int][]string `json:"users"`
	Timestamp int64            `json:"timestamp"`
	NodeID    int              `json:"node_id"`
}

func (c *APIClient) startWS(wsURL string) {
	if !c.wsStarted.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.wsStop = cancel
	go c.runWS(ctx, wsURL)
}

func (c *APIClient) runWS(ctx context.Context, wsURL string) {
	backoff := time.Second
	for {
		err := c.connectWS(ctx, wsURL)
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err != nil {
			log.Debugf("Xboard websocket disconnected: %s", err)
		}
		jitter := time.Duration(rand.Int63n(int64(backoff / 5)))
		timer := time.NewTimer(backoff + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (c *APIClient) connectWS(ctx context.Context, wsURL string) error {
	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("parse ws url: %w", err)
	}
	q := u.Query()
	q.Set("token", c.Key)
	if c.MachineID > 0 {
		q.Set("machine_id", strconv.Itoa(c.MachineID))
	} else {
		q.Set("node_id", strconv.Itoa(c.NodeID))
	}
	u.RawQuery = q.Encode()

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(10 << 20)

	writeCh := make(chan wsMessage, 16)
	c.wsMu.Lock()
	c.wsWriteCh = writeCh
	c.wsMu.Unlock()
	defer func() {
		c.wsMu.Lock()
		if c.wsWriteCh == writeCh {
			c.wsWriteCh = nil
		}
		c.wsMu.Unlock()
	}()

	done := make(chan struct{})
	var writeMu sync.Mutex
	defer close(done)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-writeCh:
				writeMu.Lock()
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				err := conn.WriteJSON(msg)
				writeMu.Unlock()
				if err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	c.sendLastWSState()

	statusTicker := time.NewTicker(10 * time.Second)
	defer statusTicker.Stop()

	errCh := make(chan error, 1)
	go func() {
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				errCh <- err
				return
			}
			c.handleWSMessage(msg, writeCh)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			writeMu.Lock()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			writeMu.Unlock()
			return nil
		case err := <-errCh:
			return fmt.Errorf("read: %w", err)
		case <-statusTicker.C:
			c.sendLastStatus()
		}
	}
}

func (c *APIClient) sendWS(event string, payload interface{}) bool {
	c.wsMu.RLock()
	writeCh := c.wsWriteCh
	c.wsMu.RUnlock()
	if writeCh == nil {
		return false
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	msg := wsMessage{Event: event, Data: data, Timestamp: time.Now().Unix()}
	select {
	case writeCh <- msg:
		return true
	default:
		log.Debugf("Xboard websocket write channel full, skip %s", event)
		return false
	}
}

func (c *APIClient) sendLastWSState() {
	c.sendLastStatus()
	c.wsMu.RLock()
	devices := cloneDeviceMap(c.lastDevices)
	c.wsMu.RUnlock()
	if len(devices) > 0 {
		c.sendWS(wsEventReportDevices, c.deviceReportPayload(devices))
	}
}

func (c *APIClient) sendLastStatus() {
	c.wsMu.RLock()
	status := cloneAnyMap(c.lastStatus)
	c.wsMu.RUnlock()
	if len(status) > 0 {
		c.sendWS("node.status", c.nodeStatusWSPayload(status))
	}
}

func (c *APIClient) handleWSMessage(msg wsMessage, writeCh chan<- wsMessage) {
	switch msg.Event {
	case "ping":
		select {
		case writeCh <- wsMessage{Event: "pong", Timestamp: time.Now().Unix()}:
		default:
		}
	case "auth.success":
		return
	case wsEventSyncConfig:
		var payload syncConfigPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Debugf("decode Xboard sync.config failed: %s", err)
			return
		}
		if payload.NodeID > 0 && c.MachineID > 0 && payload.NodeID != c.NodeID {
			return
		}
		if payload.Config.NodeID == 0 {
			payload.Config.NodeID = payload.NodeID
		}
		if payload.Config.ServerPort > 0 {
			c.setNode(&payload.Config)
		}
	case wsEventSyncUsers:
		var payload syncUsersPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Debugf("decode Xboard sync.users failed: %s", err)
			return
		}
		if payload.NodeID > 0 && c.MachineID > 0 && payload.NodeID != c.NodeID {
			return
		}
		c.setUsers(payload.Users)
	case wsEventSyncUserDelta:
		var payload syncUserDeltaPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Debugf("decode Xboard sync.user.delta failed: %s", err)
			return
		}
		if payload.NodeID > 0 && c.MachineID > 0 && payload.NodeID != c.NodeID {
			return
		}
		c.applyUserDelta(payload.Action, payload.Users)
	case wsEventSyncDevices:
		// XrayR's existing controller reports local alive IPs; global
		// multi-node device state needs a deeper limiter integration.
		return
	}
}

func (c *APIClient) deviceReportPayload(devices map[int][]string) interface{} {
	if c.MachineID > 0 && c.NodeID > 0 {
		return map[string]interface{}{
			"node_id": c.NodeID,
			"devices": devices,
		}
	}
	return devices
}

func (c *APIClient) nodeStatusWSPayload(status map[string]interface{}) map[string]interface{} {
	payload := cloneAnyMap(status)
	if c.MachineID > 0 && c.NodeID > 0 {
		payload["node_id"] = c.NodeID
	}
	return payload
}

func cloneDeviceMap(src map[int][]string) map[int][]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[int][]string, len(src))
	for uid, ips := range src {
		if len(ips) == 0 {
			out[uid] = nil
			continue
		}
		out[uid] = append([]string(nil), ips...)
	}
	return out
}

func cloneAnyMap(src map[string]interface{}) map[string]interface{} {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (c *APIClient) applyUserDelta(action string, delta []user) {
	if len(delta) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	byID := make(map[int]user, len(c.users)+len(delta))
	for _, item := range c.users {
		byID[item.ID] = item
	}
	switch action {
	case "add", "update":
		for _, item := range delta {
			byID[item.ID] = item
		}
	case "remove", "delete":
		for _, item := range delta {
			delete(byID, item.ID)
		}
	default:
		return
	}

	c.users = c.users[:0]
	for _, item := range byID {
		c.users = append(c.users, item)
	}
	c.userVer++
}
