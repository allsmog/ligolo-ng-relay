// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy"
)

const (
	routeDecisionApply        = "apply"
	routeDecisionSkipConflict = "skip_conflict"
)

type ChainRoutePlan struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Status      string                `json:"status"`
	Summary     ChainRoutePlanSummary `json:"summary"`
	Warnings    []string              `json:"warnings,omitempty"`
	Decisions   []ChainRouteDecision  `json:"decisions"`
}

type ChainRoutePlanSummary struct {
	Candidates        int `json:"candidates"`
	Apply             int `json:"apply"`
	Skipped           int `json:"skipped"`
	ConflictGroups    int `json:"conflict_groups"`
	AlreadyConfigured int `json:"already_configured"`
	StartTunnels      int `json:"start_tunnels"`
}

type ChainRouteDecision struct {
	AgentID           int    `json:"agent_id"`
	Name              string `json:"name"`
	SessionID         string `json:"session_id"`
	ParentSessionID   string `json:"parent_session_id"`
	HopDepth          int    `json:"hop_depth"`
	Interface         string `json:"interface"`
	Route             string `json:"route"`
	RouteKey          string `json:"route_key"`
	Decision          string `json:"decision"`
	Reason            string `json:"reason"`
	Conflict          bool   `json:"conflict"`
	ConflictWith      []int  `json:"conflict_with,omitempty"`
	Preferred         bool   `json:"preferred"`
	Score             int    `json:"score"`
	Alive             bool   `json:"alive"`
	AgentState        string `json:"agent_state"`
	PathRTTMS         *int64 `json:"path_rtt_ms,omitempty"`
	TunnelRunning     bool   `json:"tunnel_running"`
	RelayActive       bool   `json:"relay_active"`
	AlreadyConfigured bool   `json:"already_configured"`
	StartTunnel       bool   `json:"start_tunnel"`
}

type RelayMeshHealthSummary struct {
	Total      int `json:"total"`
	Healthy    int `json:"healthy"`
	Degraded   int `json:"degraded"`
	Offline    int `json:"offline"`
	Repairable int `json:"repairable"`
}

type RelayMeshHealth struct {
	AgentID         int      `json:"agent_id"`
	Name            string   `json:"name"`
	SessionID       string   `json:"session_id"`
	ParentSessionID string   `json:"parent_session_id"`
	HopDepth        int      `json:"hop_depth"`
	State           string   `json:"state"`
	Alive           bool     `json:"alive"`
	PathRTTMS       *int64   `json:"path_rtt_ms,omitempty"`
	TunnelRunning   bool     `json:"tunnel_running"`
	RelayActive     bool     `json:"relay_active"`
	DownstreamCount int      `json:"downstream_count"`
	Issues          []string `json:"issues,omitempty"`
	RecoveryActions []string `json:"recovery_actions,omitempty"`
}

func chainRoutePlan(includeIPv6 bool, interfacePrefix string, start bool) ChainRoutePlan {
	snapshot := chainSnapshot()
	routes := chainRouteInfos(includeIPv6, interfacePrefix)
	return chainRoutePlanFromSnapshot(snapshot, routes, start)
}

func chainRoutePlanFromSnapshot(snapshot proxy.ChainSnapshot, routes []ChainRouteInfo, start bool) ChainRoutePlan {
	plan := ChainRoutePlan{
		GeneratedAt: time.Now(),
		Status:      "ok",
	}
	if len(routes) == 0 {
		plan.Warnings = append(plan.Warnings, "no route candidates available")
		plan.Status = "warning"
		return plan
	}

	nodesBySession := flattenChainNodes(snapshot.Agents)
	configured := configuredRouteKeys()
	decisions := make([]ChainRouteDecision, 0, len(routes))
	groups := make(map[string][]int)

	for _, route := range routes {
		node, ok := nodesBySession[route.SessionID]
		alive := ok && node.Alive
		agentState := "unknown"
		if ok {
			agentState = node.State
		}
		decision := ChainRouteDecision{
			AgentID:           route.AgentID,
			Name:              route.Name,
			SessionID:         route.SessionID,
			ParentSessionID:   route.ParentSessionID,
			HopDepth:          route.HopDepth,
			Interface:         route.Interface,
			Route:             route.Route,
			RouteKey:          routeConflictKey(route.Route),
			Decision:          routeDecisionApply,
			Conflict:          route.Conflict,
			ConflictWith:      append([]int(nil), route.ConflictWith...),
			Alive:             alive,
			AgentState:        agentState,
			AlreadyConfigured: routeAlreadyConfigured(configured, route.Interface, route.Route),
		}
		if ok {
			decision.PathRTTMS = cloneInt64(node.PathRTTMS)
			decision.TunnelRunning = node.TunnelRunning
			decision.RelayActive = node.RelayActive
		}
		decision.Score = routeDecisionScore(decision)
		decisions = append(decisions, decision)
		groups[decision.RouteKey] = append(groups[decision.RouteKey], len(decisions)-1)
	}

	for routeKey, indexes := range groups {
		sort.Slice(indexes, func(i, j int) bool {
			return betterRouteDecision(decisions[indexes[i]], decisions[indexes[j]])
		})
		preferredIndex := indexes[0]
		preferred := decisions[preferredIndex]
		if len(indexes) > 1 {
			plan.Summary.ConflictGroups++
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("route %s has %d candidates; selected agent %d", routeKey, len(indexes), preferred.AgentID))
		}
		for _, index := range indexes {
			decision := &decisions[index]
			decision.Conflict = len(indexes) > 1
			decision.ConflictWith = conflictPeerAgentIDs(decisions, indexes, decision.AgentID)
			if index == preferredIndex {
				decision.Decision = routeDecisionApply
				decision.Preferred = true
				decision.StartTunnel = start && decision.Alive && !decision.TunnelRunning
				decision.Reason = routeApplyReason(*decision, len(indexes) > 1)
				continue
			}
			decision.Decision = routeDecisionSkipConflict
			decision.Reason = fmt.Sprintf("skipped duplicate CIDR; agent %d has the preferred route cost", preferred.AgentID)
			decision.StartTunnel = false
		}
	}

	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].RouteKey != decisions[j].RouteKey {
			return decisions[i].RouteKey < decisions[j].RouteKey
		}
		if decisions[i].Preferred != decisions[j].Preferred {
			return decisions[i].Preferred
		}
		return decisions[i].AgentID < decisions[j].AgentID
	})

	plan.Decisions = decisions
	plan.Summary.Candidates = len(decisions)
	for _, decision := range decisions {
		if decision.Decision == routeDecisionApply {
			plan.Summary.Apply++
		} else {
			plan.Summary.Skipped++
		}
		if decision.AlreadyConfigured {
			plan.Summary.AlreadyConfigured++
		}
		if decision.StartTunnel {
			plan.Summary.StartTunnels++
		}
	}
	if plan.Summary.Skipped > 0 || len(plan.Warnings) > 0 {
		plan.Status = "warning"
	}
	return plan
}

func routeApplyReason(decision ChainRouteDecision, hadConflict bool) string {
	parts := []string{}
	if hadConflict {
		parts = append(parts, "selected preferred duplicate candidate")
	} else {
		parts = append(parts, "selected unique route candidate")
	}
	if decision.HopDepth == 0 {
		parts = append(parts, "direct agent")
	} else {
		parts = append(parts, fmt.Sprintf("%d-hop path", decision.HopDepth))
	}
	if decision.PathRTTMS != nil {
		parts = append(parts, fmt.Sprintf("%d ms RTT", *decision.PathRTTMS))
	}
	if decision.AlreadyConfigured {
		parts = append(parts, "route already configured")
	}
	if decision.StartTunnel {
		parts = append(parts, "tunnel will be started")
	}
	return strings.Join(parts, "; ")
}

func routeDecisionScore(decision ChainRouteDecision) int {
	score := 0
	if decision.Alive {
		score += 10000
	}
	score -= decision.HopDepth * 1000
	if decision.PathRTTMS == nil {
		score -= 500
	} else {
		score -= int(*decision.PathRTTMS)
	}
	if decision.TunnelRunning {
		score += 100
	}
	if decision.RelayActive {
		score += 10
	}
	return score
}

func betterRouteDecision(left, right ChainRouteDecision) bool {
	if left.Alive != right.Alive {
		return left.Alive
	}
	if left.HopDepth != right.HopDepth {
		return left.HopDepth < right.HopDepth
	}
	if (left.PathRTTMS == nil) != (right.PathRTTMS == nil) {
		return right.PathRTTMS == nil
	}
	if left.PathRTTMS != nil && right.PathRTTMS != nil && *left.PathRTTMS != *right.PathRTTMS {
		return *left.PathRTTMS < *right.PathRTTMS
	}
	if left.TunnelRunning != right.TunnelRunning {
		return left.TunnelRunning
	}
	return left.AgentID < right.AgentID
}

func conflictPeerAgentIDs(decisions []ChainRouteDecision, indexes []int, agentID int) []int {
	peers := make([]int, 0, len(indexes)-1)
	for _, index := range indexes {
		peer := decisions[index].AgentID
		if peer != agentID {
			peers = append(peers, peer)
		}
	}
	sort.Ints(peers)
	return peers
}

func configuredRouteKeys() map[string]map[string]bool {
	state, err := config.GetInterfaceConfigState()
	if err != nil {
		return nil
	}
	configured := make(map[string]map[string]bool, len(state))
	for iface, info := range state {
		if configured[iface] == nil {
			configured[iface] = make(map[string]bool)
		}
		for _, route := range info.Routes {
			configured[iface][route.Destination] = true
			configured[iface][routeConflictKey(route.Destination)] = true
		}
	}
	return configured
}

func routeAlreadyConfigured(configured map[string]map[string]bool, iface, route string) bool {
	if configured == nil {
		return false
	}
	routes, ok := configured[iface]
	if !ok {
		return false
	}
	return routes[route] || routes[routeConflictKey(route)]
}

func relayMeshHealth(report RelayDoctorReport) []RelayMeshHealth {
	relaysBySession := make(map[string]RelayDoctorRelay, len(report.Relays))
	for _, relay := range report.Relays {
		relaysBySession[relay.SessionID] = relay
	}

	var health []RelayMeshHealth
	walkChainNodes(report.Chain.Agents, func(node proxy.ChainNode) {
		item := RelayMeshHealth{
			AgentID:         node.AgentID,
			Name:            node.Name,
			SessionID:       node.SessionID,
			ParentSessionID: node.ParentSessionID,
			HopDepth:        node.HopDepth,
			State:           "healthy",
			Alive:           node.Alive,
			PathRTTMS:       cloneInt64(node.PathRTTMS),
			TunnelRunning:   node.TunnelRunning,
			RelayActive:     node.RelayActive,
			DownstreamCount: node.DownstreamCount,
		}
		if !node.Alive {
			item.Issues = appendUniqueString(item.Issues, "agent is offline")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, "wait for reconnect; matching SessionID recovery will restore tunnel, listeners, and relay state")
		}
		if node.Alive && node.PathRTTMS == nil {
			item.Issues = appendUniqueString(item.Issues, "path health probe did not complete")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, "run relayctl ops again or inspect agent transport latency")
		}
		if node.RelayActive && node.RelayTokenExpired {
			item.Issues = appendUniqueString(item.Issues, "relay auth token is expired")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, fmt.Sprintf("rotate relay token for agent %d", node.AgentID))
		}
		if node.RelayActive && node.RelayCertFingerprint == "" {
			item.Issues = appendUniqueString(item.Issues, "relay fingerprint is missing")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, fmt.Sprintf("restart relay on agent %d", node.AgentID))
		}
		if relay, ok := relaysBySession[node.SessionID]; ok {
			for _, problem := range relay.Problems {
				item.Issues = appendUniqueString(item.Issues, problem)
				item.RecoveryActions = appendUniqueString(item.RecoveryActions, fmt.Sprintf("inspect relay event history for agent %d", node.AgentID))
			}
		}
		if len(item.Issues) > 0 {
			item.State = "degraded"
		}
		if !node.Alive {
			item.State = "offline"
		}
		health = append(health, item)
	})
	return health
}

func relayMeshHealthSummary(health []RelayMeshHealth) RelayMeshHealthSummary {
	var summary RelayMeshHealthSummary
	summary.Total = len(health)
	for _, item := range health {
		switch item.State {
		case "healthy":
			summary.Healthy++
		case "offline":
			summary.Offline++
		default:
			summary.Degraded++
		}
		if len(item.RecoveryActions) > 0 {
			summary.Repairable++
		}
	}
	return summary
}

func flattenChainNodes(nodes []proxy.ChainNode) map[string]proxy.ChainNode {
	flat := make(map[string]proxy.ChainNode)
	walkChainNodes(nodes, func(node proxy.ChainNode) {
		flat[node.SessionID] = node
	})
	return flat
}

func walkChainNodes(nodes []proxy.ChainNode, visit func(proxy.ChainNode)) {
	for _, node := range nodes {
		visit(node)
		walkChainNodes(node.Children, visit)
	}
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
