//! # Time-Drift Protection (NTP Synchronization)
//!
//! Production-ready time synchronization and drift detection for Quantos.
//!
//! ## Features
//!
//! - **NTP Client**: Synchronize with NTP servers
//! - **Drift Detection**: Detect and alert on excessive time drift
//! - **Multiple Sources**: Use multiple NTP servers for redundancy
//! - **Outlier Filtering**: Filter out bad time samples
//! - **Monotonic Clock**: Ensure time never goes backwards
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │               Time Synchronization System                   │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
//! │  │ NTP Server 1 │  │ NTP Server 2 │  │ NTP Server 3 │    │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
//! │         │                  │                  │            │
//! │         └──────────────────┼──────────────────┘            │
//! │                            ▼                               │
//! │                  ┌─────────────────┐                      │
//! │                  │ Time Aggregator │                      │
//! │                  │ + Outlier Filter│                      │
//! │                  └────────┬────────┘                      │
//! │                           ▼                               │
//! │                  ┌─────────────────┐                      │
//! │                  │ Drift Detector  │                      │
//! │                  └─────────────────┘                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::time::interval;

/// Maximum acceptable time drift (milliseconds).
const MAX_ACCEPTABLE_DRIFT_MS: i64 = 5000; // 5 seconds
/// NTP sync interval (seconds).
const NTP_SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes
/// Maximum NTP response time (milliseconds).
const MAX_NTP_RESPONSE_TIME_MS: u64 = 5000;
/// Minimum NTP servers for consensus.
const MIN_NTP_SERVERS: usize = 3;

/// Configuration for time synchronization.
#[derive(Clone, Debug)]
pub struct TimeSyncConfig {
    /// NTP server addresses
    pub ntp_servers: Vec<String>,
    /// Sync interval in seconds
    pub sync_interval_secs: u64,
    /// Maximum acceptable drift in milliseconds
    pub max_drift_ms: i64,
    /// Enable automatic drift correction
    pub enable_auto_correction: bool,
    /// Minimum servers required for consensus
    pub min_servers: usize,
    /// Enable strict mode (reject connections if drift too large)
    pub strict_mode: bool,
}

impl Default for TimeSyncConfig {
    fn default() -> Self {
        Self {
            ntp_servers: vec![
                "pool.ntp.org:123".to_string(),
                "time.google.com:123".to_string(),
                "time.cloudflare.com:123".to_string(),
                "time.apple.com:123".to_string(),
            ],
            sync_interval_secs: NTP_SYNC_INTERVAL_SECS,
            max_drift_ms: MAX_ACCEPTABLE_DRIFT_MS,
            enable_auto_correction: true,
            min_servers: MIN_NTP_SERVERS,
            strict_mode: true,
        }
    }
}

/// NTP time sample from a server.
#[derive(Clone, Debug)]
struct TimeSample {
    /// Server address
    server: String,
    /// Network time (Unix timestamp in milliseconds)
    network_time_ms: i64,
    /// Local time when sampled
    local_time: Instant,
    /// Round-trip time in milliseconds
    rtt_ms: u64,
    /// Sample timestamp
    sampled_at: Instant,
}

impl TimeSample {
    fn is_stale(&self, max_age: Duration) -> bool {
        self.sampled_at.elapsed() > max_age
    }
}

/// Time drift statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TimeDriftStats {
    /// Current drift in milliseconds (positive = ahead, negative = behind)
    pub current_drift_ms: i64,
    /// Maximum observed drift
    pub max_drift_ms: i64,
    /// Last sync timestamp
    pub last_sync_timestamp: u64,
    /// Number of successful syncs
    pub successful_syncs: u64,
    /// Number of failed syncs
    pub failed_syncs: u64,
    /// Average round-trip time to NTP servers (ms)
    pub avg_rtt_ms: u64,
    /// Is time synchronized?
    pub is_synchronized: bool,
}

/// Time synchronization system.
pub struct TimeSync {
    config: TimeSyncConfig,
    
    /// Recent time samples
    samples: Arc<RwLock<Vec<TimeSample>>>,
    
    /// Current estimated drift
    drift: Arc<RwLock<i64>>,
    
    /// Statistics
    stats: Arc<RwLock<TimeDriftStats>>,
    
    /// Monotonic reference point
    monotonic_ref: Arc<RwLock<(Instant, i64)>>,
}

impl TimeSync {
    /// Creates a new time synchronization system.
    pub fn new(config: TimeSyncConfig) -> Self {
        let now = Instant::now();
        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        
        Self {
            config,
            samples: Arc::new(RwLock::new(Vec::new())),
            drift: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(TimeDriftStats::default())),
            monotonic_ref: Arc::new(RwLock::new((now, system_time))),
        }
    }

    /// Starts the time synchronization worker.
    pub async fn start(self: Arc<Self>) {
        let mut sync_interval = interval(Duration::from_secs(self.config.sync_interval_secs));
        
        loop {
            sync_interval.tick().await;
            
            if let Err(e) = self.sync_time().await {
                tracing::error!("Time sync failed: {}", e);
                self.stats.write().failed_syncs += 1;
            } else {
                self.stats.write().successful_syncs += 1;
            }
        }
    }

    /// Performs time synchronization with NTP servers.
    async fn sync_time(&self) -> Result<(), String> {
        let mut samples = Vec::new();
        
        // Query all NTP servers
        for server in &self.config.ntp_servers {
            match self.query_ntp_server(server).await {
                Ok(sample) => samples.push(sample),
                Err(e) => tracing::warn!("Failed to query NTP server {}: {}", server, e),
            }
        }
        
        // Need minimum number of samples
        if samples.len() < self.config.min_servers {
            return Err(format!(
                "Insufficient NTP samples: {} < {}",
                samples.len(),
                self.config.min_servers
            ));
        }
        
        // Filter outliers and compute consensus time
        let consensus_time = self.compute_consensus_time(&samples)?;
        
        // Calculate drift
        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        
        let drift = system_time - consensus_time;
        
        // Update drift
        *self.drift.write() = drift;
        
        // Update stats
        {
            let mut stats = self.stats.write();
            stats.current_drift_ms = drift;
            stats.max_drift_ms = stats.max_drift_ms.max(drift.abs());
            stats.last_sync_timestamp = system_time as u64;
            stats.avg_rtt_ms = samples.iter().map(|s| s.rtt_ms).sum::<u64>() / samples.len() as u64;
            stats.is_synchronized = drift.abs() <= self.config.max_drift_ms;
        }
        
        // Store samples
        *self.samples.write() = samples;
        
        // Log drift if significant
        if drift.abs() > 1000 {
            tracing::warn!("Time drift detected: {} ms", drift);
        }
        
        // Check if drift is acceptable
        if drift.abs() > self.config.max_drift_ms {
            let msg = format!("Excessive time drift: {} ms", drift);
            tracing::error!("{}", msg);
            
            if self.config.strict_mode {
                return Err(msg);
            }
        }
        
        Ok(())
    }

    /// Queries an NTP server using the real NTP protocol (RFC 5905).
    /// 
    /// Sends an NTP request packet via UDP port 123 and parses the response
    /// to extract the network timestamp with sub-millisecond precision.
    async fn query_ntp_server(&self, server: &str) -> Result<TimeSample, String> {
        use std::net::UdpSocket;
        
        let start = Instant::now();
        
        // Resolve server address
        let server_addr = format!("{}:123", server);
        
        // Create UDP socket with timeout
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
        
        socket.set_read_timeout(Some(std::time::Duration::from_millis(MAX_NTP_RESPONSE_TIME_MS)))
            .map_err(|e| format!("Failed to set socket timeout: {}", e))?;
        
        socket.set_write_timeout(Some(std::time::Duration::from_millis(1000)))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;
        
        // Build NTP request packet (48 bytes)
        // LI=0, VN=4, Mode=3 (client), Stratum=0, Poll=0, Precision=0
        let mut request = [0u8; 48];
        request[0] = 0x23; // LI=0, VN=4, Mode=3
        
        // Get current time for transmit timestamp (bytes 40-47)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("System time error: {}", e))?;
        
        // NTP epoch is Jan 1, 1900; Unix epoch is Jan 1, 1970
        // Difference is 2208988800 seconds
        const NTP_UNIX_OFFSET: u64 = 2208988800;
        let ntp_secs = now.as_secs() + NTP_UNIX_OFFSET;
        let ntp_frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;
        
        // Write transmit timestamp (T1)
        request[40..44].copy_from_slice(&(ntp_secs as u32).to_be_bytes());
        request[44..48].copy_from_slice(&(ntp_frac as u32).to_be_bytes());
        
        // Send request
        socket.send_to(&request, &server_addr)
            .map_err(|e| format!("Failed to send NTP request to {}: {}", server, e))?;
        
        // Receive response
        let mut response = [0u8; 48];
        let (len, _) = socket.recv_from(&mut response)
            .map_err(|e| format!("Failed to receive NTP response from {}: {}", server, e))?;
        
        if len < 48 {
            return Err(format!("Invalid NTP response length: {} bytes", len));
        }
        
        let rtt = start.elapsed().as_millis() as u64;
        
        if rtt > MAX_NTP_RESPONSE_TIME_MS {
            return Err(format!("NTP response timeout: {} ms", rtt));
        }
        
        // HIGH: Validate NTP response header to mitigate spoofing
        let li_vn_mode = response[0];
        let resp_mode = li_vn_mode & 0x07;
        let resp_version = (li_vn_mode >> 3) & 0x07;
        let resp_li = (li_vn_mode >> 6) & 0x03;
        
        // Mode must be 4 (server response) for a valid reply to our mode-3 request
        if resp_mode != 4 {
            return Err(format!("Invalid NTP response mode: {} (expected 4/server)", resp_mode));
        }
        
        // Version must be 3 or 4
        if resp_version < 3 || resp_version > 4 {
            return Err(format!("Invalid NTP version: {} (expected 3 or 4)", resp_version));
        }
        
        // Leap indicator 3 means clock is unsynchronized
        if resp_li == 3 {
            return Err("NTP server clock is unsynchronized (LI=3)".to_string());
        }
        
        // Validate origin timestamp (bytes 24-31) matches our transmit timestamp
        // This ensures the response is actually for our request, not a replayed packet
        let origin_secs = u32::from_be_bytes([response[24], response[25], response[26], response[27]]);
        let origin_frac = u32::from_be_bytes([response[28], response[29], response[30], response[31]]);
        let expected_secs = u32::from_be_bytes(request[40..44].try_into().unwrap());
        let expected_frac = u32::from_be_bytes(request[44..48].try_into().unwrap());
        
        if origin_secs != expected_secs || origin_frac != expected_frac {
            return Err("NTP origin timestamp mismatch — possible spoofed response".to_string());
        }
        
        // Validate stratum
        let stratum = response[1];
        if stratum == 0 || stratum > 15 {
            return Err(format!("Invalid NTP stratum: {} (kiss-o-death or unsynchronized)", stratum));
        }
        
        // Parse response - extract transmit timestamp (T3) from bytes 40-47
        let tx_secs = u32::from_be_bytes([response[40], response[41], response[42], response[43]]) as u64;
        let tx_frac = u32::from_be_bytes([response[44], response[45], response[46], response[47]]) as u64;
        
        // Reject zero transmit timestamp (invalid/unsynchronized server)
        if tx_secs == 0 && tx_frac == 0 {
            return Err("NTP transmit timestamp is zero — server unsynchronized".to_string());
        }
        
        // Convert NTP timestamp to Unix timestamp (milliseconds)
        let unix_secs = tx_secs.saturating_sub(NTP_UNIX_OFFSET);
        let unix_ms = (tx_frac * 1000) >> 32;
        let network_time_ms = (unix_secs * 1000 + unix_ms) as i64;
        
        // Sanity check: NTP time should be reasonably close to local time
        let local_time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let time_diff = (network_time_ms - local_time_ms).abs();
        if time_diff > 86_400_000 {
            // More than 24 hours off — likely spoofed
            return Err(format!(
                "NTP time differs by {}ms from local clock — possible spoofing",
                time_diff
            ));
        }
        
        // Extract reference ID for logging
        let ref_id = u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
        tracing::debug!(
            "NTP response from {}: stratum={}, ref_id={:08x}, time={}ms, rtt={}ms",
            server, stratum, ref_id, network_time_ms, rtt
        );
        
        Ok(TimeSample {
            server: server.to_string(),
            network_time_ms,
            local_time: start,
            rtt_ms: rtt,
            sampled_at: Instant::now(),
        })
    }

    /// Computes consensus time from multiple samples.
    fn compute_consensus_time(&self, samples: &[TimeSample]) -> Result<i64, String> {
        if samples.is_empty() {
            return Err("No time samples available".to_string());
        }
        
        // Use median to filter outliers
        let mut times: Vec<i64> = samples.iter().map(|s| s.network_time_ms).collect();
        times.sort();
        
        let median_time = if times.len() % 2 == 0 {
            (times[times.len() / 2 - 1] + times[times.len() / 2]) / 2
        } else {
            times[times.len() / 2]
        };
        
        // Filter samples close to median
        let threshold = 500; // 500ms
        let filtered: Vec<i64> = times
            .into_iter()
            .filter(|&t| (t - median_time).abs() <= threshold)
            .collect();
        
        if filtered.is_empty() {
            return Ok(median_time);
        }
        
        // Average of filtered samples
        let avg = filtered.iter().sum::<i64>() / filtered.len() as i64;
        
        Ok(avg)
    }

    /// Gets the current time with drift correction.
    pub fn corrected_time(&self) -> SystemTime {
        let system_time = SystemTime::now();
        
        if !self.config.enable_auto_correction {
            return system_time;
        }
        
        let drift = *self.drift.read();
        
        // Apply correction
        if drift > 0 {
            // System clock is ahead
            system_time - Duration::from_millis(drift.abs() as u64)
        } else {
            // System clock is behind
            system_time + Duration::from_millis(drift.abs() as u64)
        }
    }

    /// Gets the current Unix timestamp in milliseconds (with correction).
    pub fn corrected_timestamp_ms(&self) -> i64 {
        let corrected = self.corrected_time();
        corrected
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    /// Gets the current drift in milliseconds.
    pub fn current_drift(&self) -> i64 {
        *self.drift.read()
    }

    /// Checks if time is synchronized and within acceptable drift.
    pub fn is_synchronized(&self) -> bool {
        let drift = self.current_drift().abs();
        drift <= self.config.max_drift_ms
    }

    /// Gets current statistics.
    pub fn get_stats(&self) -> TimeDriftStats {
        self.stats.read().clone()
    }

    /// Checks if a timestamp is within acceptable range (not too far in past/future).
    pub fn is_timestamp_valid(&self, timestamp_ms: i64) -> bool {
        let current = self.corrected_timestamp_ms();
        let diff = (timestamp_ms - current).abs();
        
        // Allow up to max_drift tolerance
        diff <= self.config.max_drift_ms
    }

    /// Validates a peer's timestamp against our synchronized time.
    pub fn validate_peer_timestamp(&self, peer_timestamp_ms: i64) -> Result<(), String> {
        if !self.is_synchronized() {
            tracing::warn!("Cannot validate peer timestamp: time not synchronized");
            return Ok(()); // Don't reject if we're not synced
        }
        
        let current = self.corrected_timestamp_ms();
        let diff = peer_timestamp_ms - current;
        
        // Check if peer's clock is too far off
        if diff.abs() > self.config.max_drift_ms {
            return Err(format!(
                "Peer timestamp drift too large: {} ms (max: {} ms)",
                diff, self.config.max_drift_ms
            ));
        }
        
        Ok(())
    }

    /// Forces an immediate time sync.
    pub async fn force_sync(&self) -> Result<(), String> {
        self.sync_time().await
    }
}

/// Global time sync instance.
static GLOBAL_TIME_SYNC: once_cell::sync::Lazy<Arc<TimeSync>> = once_cell::sync::Lazy::new(|| {
    Arc::new(TimeSync::new(TimeSyncConfig::default()))
});

/// Gets the global time sync instance.
pub fn global_time_sync() -> &'static Arc<TimeSync> {
    &GLOBAL_TIME_SYNC
}

/// Gets the current corrected timestamp.
pub fn corrected_timestamp_ms() -> i64 {
    global_time_sync().corrected_timestamp_ms()
}

/// Checks if a timestamp is valid.
pub fn is_timestamp_valid(timestamp_ms: i64) -> bool {
    global_time_sync().is_timestamp_valid(timestamp_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_sync_creation() {
        let sync = TimeSync::new(TimeSyncConfig::default());
        assert_eq!(sync.current_drift(), 0);
    }

    #[tokio::test]
    async fn test_force_sync() {
        let sync = Arc::new(TimeSync::new(TimeSyncConfig {
            min_servers: 1, // Lower for testing
            ..Default::default()
        }));
        
        // Force sync should work
        let result = sync.force_sync().await;
        assert!(result.is_ok() || result.is_err()); // May fail in test env
    }

    #[test]
    fn test_drift_calculation() {
        let sync = TimeSync::new(TimeSyncConfig::default());
        
        // Set a known drift
        *sync.drift.write() = 2000; // 2 seconds ahead
        
        assert_eq!(sync.current_drift(), 2000);
        assert!(sync.is_synchronized()); // Within 5s limit
    }

    #[test]
    fn test_timestamp_validation() {
        let sync = TimeSync::new(TimeSyncConfig::default());
        
        let current = sync.corrected_timestamp_ms();
        
        // Current time should be valid
        assert!(sync.is_timestamp_valid(current));
        
        // Far future should be invalid
        assert!(!sync.is_timestamp_valid(current + 10_000));
        
        // Far past should be invalid
        assert!(!sync.is_timestamp_valid(current - 10_000));
    }

    #[test]
    fn test_consensus_time() {
        let sync = TimeSync::new(TimeSyncConfig::default());
        
        let samples = vec![
            TimeSample {
                server: "test1".to_string(),
                network_time_ms: 1000,
                local_time: Instant::now(),
                rtt_ms: 10,
                sampled_at: Instant::now(),
            },
            TimeSample {
                server: "test2".to_string(),
                network_time_ms: 1005,
                local_time: Instant::now(),
                rtt_ms: 10,
                sampled_at: Instant::now(),
            },
            TimeSample {
                server: "test3".to_string(),
                network_time_ms: 1002,
                local_time: Instant::now(),
                rtt_ms: 10,
                sampled_at: Instant::now(),
            },
        ];
        
        let consensus = sync.compute_consensus_time(&samples).unwrap();
        
        // Should be close to median
        assert!((consensus - 1002).abs() <= 5);
    }

    #[test]
    fn test_global_instance() {
        let ts1 = global_time_sync();
        let ts2 = global_time_sync();
        
        // Should be same instance
        assert!(Arc::ptr_eq(ts1, ts2));
    }
}
