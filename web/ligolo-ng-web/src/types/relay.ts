export interface RelayOpsReport {
  generated_at: string;
  status: "ok" | "warning" | string;
  summary: RelayOpsSummary;
  warnings?: string[];
  actions?: RelayOpsAction[];
  chain: ChainSnapshot;
  routes?: ChainRouteInfo[];
  relays?: RelayDoctorRelay[];
  route_plan: ChainRoutePlan;
  mesh_health?: RelayMeshHealth[];
  repair_plan: ChainRepairPlan;
}

export interface RelayOpsSummary {
  agents_total: number;
  agents_online: number;
  direct_agents: number;
  relayed_agents: number;
  active_relays: number;
  downstream_agents: number;
  expired_tokens: number;
  route_conflicts: number;
  route_plan_apply: number;
  route_plan_skipped: number;
  mesh_healthy: number;
  mesh_degraded: number;
  mesh_offline: number;
  mesh_repairable: number;
  repair_actions: number;
  repair_automated: number;
  repair_manual: number;
  warnings: number;
  max_depth: number;
}

export interface RelayOpsAction {
  severity: "critical" | "warning" | string;
  agent_id?: number;
  title: string;
  detail?: string;
}

export interface ChainSnapshot {
  topology: string;
  max_depth: number;
  agents: ChainNode[];
}

export interface ChainNode {
  agent_id: number;
  name: string;
  session_id: string;
  remote_addr: string;
  parent_session_id: string;
  hop_depth: number;
  alive: boolean;
  state: string;
  path_rtt_ms?: number;
  tunnel_running: boolean;
  relay_active: boolean;
  relay_listen_addr: string;
  relay_fingerprint?: string;
  relay_token_expires_at?: string;
  relay_token_expired: boolean;
  relay_one_time_token: boolean;
  downstream_count: number;
  children?: ChainNode[];
}

export interface ChainRouteInfo {
  agent_id: number;
  name: string;
  session_id: string;
  parent_session_id: string;
  hop_depth: number;
  interface: string;
  route: string;
  conflict: boolean;
  conflict_with?: number[];
  warning?: string;
}

export interface ChainRoutePlan {
  generated_at: string;
  status: "ok" | "warning" | string;
  summary: ChainRoutePlanSummary;
  warnings?: string[];
  decisions: ChainRouteDecision[];
}

export interface ChainRoutePlanSummary {
  candidates: number;
  apply: number;
  skipped: number;
  conflict_groups: number;
  already_configured: number;
  start_tunnels: number;
}

export interface ChainRouteDecision {
  agent_id: number;
  name: string;
  session_id: string;
  parent_session_id: string;
  hop_depth: number;
  interface: string;
  route: string;
  route_key: string;
  decision: "apply" | "skip_conflict" | string;
  reason: string;
  conflict: boolean;
  conflict_with?: number[];
  preferred: boolean;
  score: number;
  alive: boolean;
  agent_state: string;
  path_rtt_ms?: number;
  tunnel_running: boolean;
  relay_active: boolean;
  already_configured: boolean;
  start_tunnel: boolean;
}

export interface RelayMeshHealth {
  agent_id: number;
  name: string;
  session_id: string;
  parent_session_id: string;
  hop_depth: number;
  state: "healthy" | "degraded" | "offline" | string;
  alive: boolean;
  path_rtt_ms?: number;
  tunnel_running: boolean;
  relay_active: boolean;
  downstream_count: number;
  issues?: string[];
  recovery_actions?: string[];
}

export interface ChainRepairPlan {
  generated_at: string;
  status: "ok" | "warning" | "error" | string;
  summary: ChainRepairPlanSummary;
  actions: ChainRepairAction[];
}

export interface ChainRepairPlanSummary {
  actions: number;
  apply_supported: number;
  applied: number;
  failed: number;
  route_ensures: number;
  tunnel_starts: number;
  prunes: number;
  manual: number;
}

export interface ChainRepairAction {
  type: string;
  severity: "critical" | "warning" | "info" | string;
  agent_id?: number;
  name?: string;
  session_id?: string;
  interface?: string;
  route?: string;
  route_key?: string;
  reason: string;
  apply_supported: boolean;
  applied: boolean;
  error?: string;
}

export interface RelayDoctorRelay {
  agent_id: number;
  name: string;
  session_id: string;
  alive: boolean;
  relay: RelayStatus;
  problems?: string[];
}

export interface RelayStatus {
  active: boolean;
  listen_addr?: string;
  fingerprint?: string;
  token_expires_at?: string;
  token_expired: boolean;
  one_time_token: boolean;
  one_time_token_used: boolean;
  last_error?: string;
  last_error_at?: string;
  recent_events?: RelayEvent[];
}

export interface RelayEvent {
  at: string;
  kind: string;
  remote_addr?: string;
  message: string;
}
