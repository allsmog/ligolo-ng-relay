export interface RelayOpsReport {
  generated_at: string;
  status: "ok" | "warning" | string;
  summary: RelayOpsSummary;
  warnings?: string[];
  actions?: RelayOpsAction[];
  chain: ChainSnapshot;
  routes?: ChainRouteInfo[];
  relays?: RelayDoctorRelay[];
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
