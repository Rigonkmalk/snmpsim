//! SNMP UDP server.
//!
//! Listens on one or more UDP endpoints (IPv4 and/or IPv6) and responds to
//! SNMP v1/v2c GET, GETNEXT and GETBULK requests from simulation data files.
//!
//! SNMPv3 packets are recognised but responded to with a Report PDU indicating
//! that the v3 engine is not supported; users should configure v1/v2c.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::ber::{
    decode_message, encode_response, error_status, GetBulkPdu, Pdu, VarBind, VarBindPdu,
};
use crate::datafile::DataFile;
use crate::error::{Result, SnmpsimError};
use crate::oid::Oid;
use crate::reporting::ReportingManager;
use crate::snmp_value::SnmpValue;

// ─── Engine configuration ─────────────────────────────────────────────────────

/// Configuration for a single SNMP engine (v3 engine ID + its community mappings).
pub struct EngineConfig {
    /// The engine ID (hex string or "auto").
    pub engine_id: String,
    /// Community name → data file mapping.
    pub communities: HashMap<String, Arc<DataFile>>,
    /// UDP v4 endpoints to listen on.
    pub udpv4_endpoints: Vec<SocketAddr>,
    /// UDP v6 endpoints to listen on.
    pub udpv6_endpoints: Vec<SocketAddr>,
    /// Maximum variable bindings per response.
    pub max_var_binds: usize,
}

impl EngineConfig {
    pub fn new(engine_id: impl Into<String>) -> Self {
        EngineConfig {
            engine_id: engine_id.into(),
            communities: HashMap::new(),
            udpv4_endpoints: Vec::new(),
            udpv6_endpoints: Vec::new(),
            max_var_binds: 64,
        }
    }

    /// Register a community name → data file mapping.
    pub fn add_community(&mut self, community: &str, data_file: Arc<DataFile>) {
        info!("Community '{}' → {}", community, data_file.path.display());
        self.communities.insert(community.to_string(), data_file);
    }
}

// ─── Shared server state ──────────────────────────────────────────────────────

/// State shared across all UDP listener tasks.
pub struct ServerState {
    /// All community → data file mappings across all engines.
    communities: HashMap<String, Arc<DataFile>>,
    pub max_var_binds: usize,
    pub reporting: Arc<ReportingManager>,
}

impl ServerState {
    pub fn new(max_var_binds: usize, reporting: Arc<ReportingManager>) -> Self {
        ServerState {
            communities: HashMap::new(),
            max_var_binds,
            reporting,
        }
    }

    pub fn add_engine(&mut self, engine: EngineConfig) {
        for (community, data_file) in engine.communities {
            self.communities.insert(community, data_file);
        }
    }

    /// Look up a data file by community name.
    pub fn find_data_file(&self, community: &[u8]) -> Option<&Arc<DataFile>> {
        let community_str = String::from_utf8_lossy(community);
        self.communities.get(community_str.as_ref())
    }
}

// ─── SNMP request processing ──────────────────────────────────────────────────

/// Process a received UDP datagram and return the response bytes (or None if no response).
pub fn process_packet(
    data: &[u8],
    peer_addr: SocketAddr,
    state: &ServerState,
) -> Option<Vec<u8>> {
    // Parse the SNMP message
    let message = match decode_message(data) {
        Ok(m) => m,
        Err(e) => {
            warn!("BER decode error from {}: {}", peer_addr, e);
            return None;
        }
    };

    let version = message.version;

    // SNMPv3 (version == 3) is not fully supported - drop silently
    if version == 3 {
        debug!("SNMPv3 message from {} - not supported, dropping", peer_addr);
        return None;
    }

    let community = &message.community;
    let community_str = String::from_utf8_lossy(community);

    debug!(
        "SNMP v{} from {} community '{}'",
        version + 1,
        peer_addr,
        community_str
    );

    // Look up data file
    let data_file = match state.find_data_file(community) {
        Some(df) => df,
        None => {
            warn!(
                "Unknown community '{}' from {} - no data file",
                community_str, peer_addr
            );
            return None;
        }
    };

    // Process the PDU
    let response = match &message.pdu {
        Pdu::GetRequest(pdu) => {
            process_get(pdu, data_file, version, community, state.max_var_binds)
        }
        Pdu::GetNextRequest(pdu) => {
            process_get_next(pdu, data_file, version, community, state.max_var_binds)
        }
        Pdu::GetBulkRequest(pdu) => {
            process_get_bulk(pdu, data_file, version, community, state.max_var_binds)
        }
        Pdu::SetRequest(pdu) => {
            process_set(pdu, data_file, version, community)
        }
        Pdu::GetResponse(_) => {
            debug!("Ignoring GetResponse PDU from {}", peer_addr);
            return None;
        }
        Pdu::Unknown(tag) => {
            warn!("Unknown PDU type 0x{:02x} from {}", tag, peer_addr);
            return None;
        }
    };

    // Update reporting metrics
    state.reporting.update(
        &data_file.path.to_string_lossy(),
        true,
        true,
        false,
        0,
    );

    Some(response)
}

fn process_get(
    pdu: &VarBindPdu,
    data_file: &DataFile,
    version: i64,
    community: &[u8],
    max_var_binds: usize,
) -> Vec<u8> {
    let requests: Vec<(Oid, SnmpValue)> = pdu
        .var_binds
        .iter()
        .map(|vb| (vb.oid.clone(), SnmpValue::Null))
        .collect();

    debug!("GET {} var-binds", requests.len());

    let responses = data_file.process_var_binds(&requests, false, false);

    let response_vbs: Vec<VarBind> = responses
        .into_iter()
        .take(max_var_binds)
        .map(|(oid, val)| VarBind { oid, value: val })
        .collect();

    encode_response(
        version,
        community,
        pdu.request_id,
        error_status::NO_ERROR,
        0,
        &response_vbs,
    )
}

fn process_get_next(
    pdu: &VarBindPdu,
    data_file: &DataFile,
    version: i64,
    community: &[u8],
    max_var_binds: usize,
) -> Vec<u8> {
    let requests: Vec<(Oid, SnmpValue)> = pdu
        .var_binds
        .iter()
        .map(|vb| (vb.oid.clone(), SnmpValue::Null))
        .collect();

    debug!("GETNEXT {} var-binds", requests.len());

    let responses = data_file.process_var_binds(&requests, true, false);

    let response_vbs: Vec<VarBind> = responses
        .into_iter()
        .take(max_var_binds)
        .map(|(oid, val)| VarBind { oid, value: val })
        .collect();

    encode_response(
        version,
        community,
        pdu.request_id,
        error_status::NO_ERROR,
        0,
        &response_vbs,
    )
}

fn process_get_bulk(
    pdu: &GetBulkPdu,
    data_file: &DataFile,
    version: i64,
    community: &[u8],
    max_var_binds: usize,
) -> Vec<u8> {
    let non_repeaters = pdu.non_repeaters.max(0) as usize;
    let max_repetitions = pdu.max_repetitions.max(0) as usize;
    let var_binds = &pdu.var_binds;

    debug!(
        "GETBULK non-repeaters={} max-repetitions={} {} var-binds",
        non_repeaters,
        max_repetitions,
        var_binds.len()
    );

    let mut response_vbs: Vec<VarBind> = Vec::new();

    // Non-repeating portion: single GETNEXT for each
    let nr_count = non_repeaters.min(var_binds.len());
    let nr_requests: Vec<(Oid, SnmpValue)> = var_binds[..nr_count]
        .iter()
        .map(|vb| (vb.oid.clone(), SnmpValue::Null))
        .collect();

    if !nr_requests.is_empty() {
        let responses = data_file.process_var_binds(&nr_requests, true, false);
        for (oid, val) in responses {
            response_vbs.push(VarBind { oid, value: val });
        }
    }

    // Repeating portion
    let repeating_vbs = &var_binds[nr_count..];
    let mut current_oids: Vec<Oid> = repeating_vbs.iter().map(|vb| vb.oid.clone()).collect();

    for _ in 0..max_repetitions {
        if current_oids.is_empty() || response_vbs.len() >= max_var_binds {
            break;
        }

        let requests: Vec<(Oid, SnmpValue)> = current_oids
            .iter()
            .map(|oid| (oid.clone(), SnmpValue::Null))
            .collect();

        let responses = data_file.process_var_binds(&requests, true, false);

        let mut all_end = true;
        let mut next_oids = Vec::new();

        for (oid, val) in responses {
            match &val {
                SnmpValue::EndOfMibView => {
                    response_vbs.push(VarBind { oid: oid.clone(), value: val });
                }
                _ => {
                    all_end = false;
                    next_oids.push(oid.clone());
                    response_vbs.push(VarBind { oid, value: val });
                }
            }

            if response_vbs.len() >= max_var_binds {
                break;
            }
        }

        if all_end {
            break;
        }

        current_oids = next_oids;
    }

    encode_response(
        version,
        community,
        pdu.request_id,
        error_status::NO_ERROR,
        0,
        &response_vbs,
    )
}

fn process_set(
    pdu: &VarBindPdu,
    data_file: &DataFile,
    version: i64,
    community: &[u8],
) -> Vec<u8> {
    // SET operations are passed through to the data file; most records
    // will return noSuchInstance unless a writecache variation module is used.
    let requests: Vec<(Oid, SnmpValue)> = pdu
        .var_binds
        .iter()
        .map(|vb| (vb.oid.clone(), vb.value.clone()))
        .collect();

    debug!("SET {} var-binds", requests.len());

    let responses = data_file.process_var_binds(&requests, false, true);

    let response_vbs: Vec<VarBind> = responses
        .into_iter()
        .map(|(oid, val)| VarBind { oid, value: val })
        .collect();

    encode_response(
        version,
        community,
        pdu.request_id,
        error_status::NO_ERROR,
        0,
        &response_vbs,
    )
}

// ─── Async UDP listener ───────────────────────────────────────────────────────

/// Run the SNMP server on all configured endpoints.
pub async fn run(
    endpoints: Vec<SocketAddr>,
    state: Arc<ServerState>,
) -> Result<()> {
    if endpoints.is_empty() {
        return Err(SnmpsimError::Config(
            "No endpoints configured for SNMP server".into(),
        ));
    }

    let mut tasks = Vec::new();

    for addr in endpoints {
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            if let Err(e) = listen(addr, state).await {
                error!("Listener on {} failed: {}", addr, e);
            }
        }));
    }

    // Wait for all listeners (they run indefinitely)
    for task in tasks {
        let _ = task.await;
    }

    Ok(())
}

/// UDP listener loop for a single endpoint.
async fn listen(addr: SocketAddr, state: Arc<ServerState>) -> Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    info!("Listening on {} (UDP)", addr);

    let mut buf = vec![0u8; 65535];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let data = &buf[..len];

        let response = process_packet(data, peer, &state);

        if let Some(resp) = response {
            if let Err(e) = socket.send_to(&resp, peer).await {
                warn!("Failed to send response to {}: {}", peer, e);
            }
        }
    }
}
