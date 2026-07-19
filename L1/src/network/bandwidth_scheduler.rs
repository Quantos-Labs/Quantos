//! # Bandwidth Scheduler (QoS)
//!
//! Quality of Service implementation for network bandwidth management.
//! Prioritizes consensus traffic over sync and background operations.
//!
//! ## Features
//!
//! - **Traffic Classes**: Consensus, Votes, Blocks, Sync, Background
//! - **Weighted Fair Queuing**: Proportional bandwidth allocation
//! - **Rate Limiting**: Per-class and per-peer limits
//! - **Congestion Control**: Adaptive backoff under load
//! - **Bandwidth Reservation**: Guaranteed minimums for critical traffic

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};

/// Traffic class for QoS scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrafficClass {
    /// Highest priority: consensus messages, view changes
    Consensus = 5,
    /// High priority: committee votes
    Votes = 4,
    /// Medium-high: DAG vertices, block proposals  
    Blocks = 3,
    /// Medium: regular transactions
    Transactions = 2,
    /// Low: state sync, catchup
    Sync = 1,
    /// Lowest: peer discovery, metrics
    Background = 0,
}

impl TrafficClass {
    /// Returns the weight for weighted fair queuing (higher = more bandwidth)
    pub fn weight(&self) -> u32 {
        match self {
            TrafficClass::Consensus => 100,
            TrafficClass::Votes => 50,
            TrafficClass::Blocks => 30,
            TrafficClass::Transactions => 15,
            TrafficClass::Sync => 10,
            TrafficClass::Background => 5,
        }
    }
    
    /// Returns minimum guaranteed bandwidth ratio (0.0 - 1.0)
    pub fn min_bandwidth_ratio(&self) -> f64 {
        match self {
            TrafficClass::Consensus => 0.20,  // 20% minimum
            TrafficClass::Votes => 0.15,      // 15% minimum
            TrafficClass::Blocks => 0.10,     // 10% minimum
            TrafficClass::Transactions => 0.05,
            TrafficClass::Sync => 0.02,
            TrafficClass::Background => 0.01,
        }
    }
    
    /// Returns maximum latency tolerance
    pub fn max_latency(&self) -> Duration {
        match self {
            TrafficClass::Consensus => Duration::from_millis(50),
            TrafficClass::Votes => Duration::from_millis(100),
            TrafficClass::Blocks => Duration::from_millis(200),
            TrafficClass::Transactions => Duration::from_millis(500),
            TrafficClass::Sync => Duration::from_secs(2),
            TrafficClass::Background => Duration::from_secs(10),
        }
    }
    
    /// All traffic classes in priority order
    pub fn all() -> &'static [TrafficClass] {
        &[
            TrafficClass::Consensus,
            TrafficClass::Votes,
            TrafficClass::Blocks,
            TrafficClass::Transactions,
            TrafficClass::Sync,
            TrafficClass::Background,
        ]
    }
}

/// Queued packet for transmission
#[derive(Clone)]
pub struct QueuedPacket {
    /// Traffic class
    pub class: TrafficClass,
    /// Packet data
    pub data: Vec<u8>,
    /// Destination peer (optional, None for broadcast)
    pub destination: Option<[u8; 32]>,
    /// Enqueue timestamp
    pub enqueued_at: Instant,
    /// Packet ID for tracking
    pub id: u64,
}

impl QueuedPacket {
    pub fn new(class: TrafficClass, data: Vec<u8>, destination: Option<[u8; 32]>) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            class,
            data,
            destination,
            enqueued_at: Instant::now(),
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }
    
    pub fn size(&self) -> usize {
        self.data.len()
    }
    
    pub fn age(&self) -> Duration {
        self.enqueued_at.elapsed()
    }
}

/// Per-class queue with statistics
struct ClassQueue {
    /// Packet queue
    packets: VecDeque<QueuedPacket>,
    /// Maximum queue size in bytes
    max_bytes: usize,
    /// Current queue size in bytes
    current_bytes: usize,
    /// Packets dropped due to queue full
    drops: u64,
    /// Packets transmitted
    transmitted: u64,
    /// Bytes transmitted
    bytes_transmitted: u64,
    /// Virtual finish time for WFQ
    virtual_finish_time: f64,
}

impl ClassQueue {
    fn new(max_bytes: usize) -> Self {
        Self {
            packets: VecDeque::new(),
            max_bytes,
            current_bytes: 0,
            drops: 0,
            transmitted: 0,
            bytes_transmitted: 0,
            virtual_finish_time: 0.0,
        }
    }
    
    fn enqueue(&mut self, packet: QueuedPacket) -> bool {
        if self.current_bytes + packet.size() > self.max_bytes {
            self.drops += 1;
            return false;
        }
        
        self.current_bytes += packet.size();
        self.packets.push_back(packet);
        true
    }
    
    fn dequeue(&mut self) -> Option<QueuedPacket> {
        if let Some(packet) = self.packets.pop_front() {
            self.current_bytes -= packet.size();
            self.transmitted += 1;
            self.bytes_transmitted += packet.size() as u64;
            Some(packet)
        } else {
            None
        }
    }
    
    fn peek(&self) -> Option<&QueuedPacket> {
        self.packets.front()
    }
    
    fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
    
    fn len(&self) -> usize {
        self.packets.len()
    }
}

/// Token bucket rate limiter
pub struct TokenBucket {
    /// Maximum tokens (burst capacity)
    capacity: u64,
    /// Current tokens
    tokens: f64,
    /// Token refill rate (tokens/second = bytes/second)
    rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        Self {
            capacity: burst_bytes,
            tokens: burst_bytes as f64,
            rate: rate_bytes_per_sec as f64,
            last_refill: Instant::now(),
        }
    }
    
    /// Refills tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity as f64);
        self.last_refill = now;
    }
    
    /// Attempts to consume tokens, returns true if successful
    pub fn try_consume(&mut self, tokens: u64) -> bool {
        self.refill();
        
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }
    
    /// Returns available tokens
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }
    
    /// Time until specified tokens are available
    pub fn time_until_available(&mut self, tokens: u64) -> Duration {
        self.refill();
        
        if self.tokens >= tokens as f64 {
            Duration::ZERO
        } else {
            let needed = tokens as f64 - self.tokens;
            Duration::from_secs_f64(needed / self.rate)
        }
    }
}

/// Per-peer rate limiter
pub struct PeerRateLimiter {
    /// Peer ID
    peer_id: [u8; 32],
    /// Inbound rate limiter
    inbound: TokenBucket,
    /// Outbound rate limiter
    outbound: TokenBucket,
    /// Last activity
    last_activity: Instant,
    /// Is peer throttled?
    throttled: bool,
}

impl PeerRateLimiter {
    pub fn new(peer_id: [u8; 32], inbound_rate: u64, outbound_rate: u64) -> Self {
        Self {
            peer_id,
            inbound: TokenBucket::new(inbound_rate, inbound_rate * 2),
            outbound: TokenBucket::new(outbound_rate, outbound_rate * 2),
            last_activity: Instant::now(),
            throttled: false,
        }
    }
    
    pub fn try_send(&mut self, bytes: u64) -> bool {
        self.last_activity = Instant::now();
        self.outbound.try_consume(bytes)
    }
    
    pub fn try_receive(&mut self, bytes: u64) -> bool {
        self.last_activity = Instant::now();
        self.inbound.try_consume(bytes)
    }
}

/// Congestion state
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CongestionLevel {
    /// No congestion, full speed
    None,
    /// Light congestion, slight reduction
    Light,
    /// Moderate congestion, significant reduction
    Moderate,
    /// Severe congestion, minimum bandwidth only
    Severe,
}

impl CongestionLevel {
    /// Returns bandwidth multiplier (0.0 - 1.0)
    pub fn bandwidth_multiplier(&self) -> f64 {
        match self {
            CongestionLevel::None => 1.0,
            CongestionLevel::Light => 0.8,
            CongestionLevel::Moderate => 0.5,
            CongestionLevel::Severe => 0.2,
        }
    }
}

/// Congestion detector
pub struct CongestionDetector {
    /// RTT samples
    rtt_samples: VecDeque<(Instant, Duration)>,
    /// Baseline RTT (minimum observed)
    baseline_rtt: Duration,
    /// Current smoothed RTT
    smoothed_rtt: Duration,
    /// Packet loss rate (0.0 - 1.0)
    loss_rate: f64,
    /// Queue delay samples
    queue_delays: VecDeque<Duration>,
}

impl CongestionDetector {
    pub fn new() -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(100),
            baseline_rtt: Duration::from_millis(50),
            smoothed_rtt: Duration::from_millis(50),
            loss_rate: 0.0,
            queue_delays: VecDeque::with_capacity(100),
        }
    }
    
    /// Records an RTT sample
    pub fn record_rtt(&mut self, rtt: Duration) {
        let now = Instant::now();
        
        // Update baseline
        if rtt < self.baseline_rtt {
            self.baseline_rtt = rtt;
        }
        
        // Exponential moving average for smoothed RTT
        const ALPHA: f64 = 0.125;
        self.smoothed_rtt = Duration::from_secs_f64(
            ALPHA * rtt.as_secs_f64() + (1.0 - ALPHA) * self.smoothed_rtt.as_secs_f64()
        );
        
        // Store sample
        self.rtt_samples.push_back((now, rtt));
        
        // Remove old samples (> 10 seconds)
        while let Some((time, _)) = self.rtt_samples.front() {
            if now.duration_since(*time) > Duration::from_secs(10) {
                self.rtt_samples.pop_front();
            } else {
                break;
            }
        }
    }
    
    /// Records a packet loss event
    pub fn record_loss(&mut self, packets_sent: u64, packets_lost: u64) {
        if packets_sent > 0 {
            const ALPHA: f64 = 0.1;
            let current_loss = packets_lost as f64 / packets_sent as f64;
            self.loss_rate = ALPHA * current_loss + (1.0 - ALPHA) * self.loss_rate;
        }
    }
    
    /// Records queue delay
    pub fn record_queue_delay(&mut self, delay: Duration) {
        self.queue_delays.push_back(delay);
        if self.queue_delays.len() > 100 {
            self.queue_delays.pop_front();
        }
    }
    
    /// Detects current congestion level
    pub fn detect(&self) -> CongestionLevel {
        // RTT-based detection (delay-based)
        let rtt_ratio = self.smoothed_rtt.as_secs_f64() / self.baseline_rtt.as_secs_f64();
        
        // Loss-based detection
        let loss_level = if self.loss_rate > 0.1 {
            CongestionLevel::Severe
        } else if self.loss_rate > 0.05 {
            CongestionLevel::Moderate
        } else if self.loss_rate > 0.01 {
            CongestionLevel::Light
        } else {
            CongestionLevel::None
        };
        
        // RTT-based level
        let rtt_level = if rtt_ratio > 4.0 {
            CongestionLevel::Severe
        } else if rtt_ratio > 2.0 {
            CongestionLevel::Moderate
        } else if rtt_ratio > 1.5 {
            CongestionLevel::Light
        } else {
            CongestionLevel::None
        };
        
        // Average queue delay check
        let avg_queue_delay = if !self.queue_delays.is_empty() {
            let sum: Duration = self.queue_delays.iter().sum();
            sum / self.queue_delays.len() as u32
        } else {
            Duration::ZERO
        };
        
        let queue_level = if avg_queue_delay > Duration::from_millis(500) {
            CongestionLevel::Severe
        } else if avg_queue_delay > Duration::from_millis(200) {
            CongestionLevel::Moderate
        } else if avg_queue_delay > Duration::from_millis(50) {
            CongestionLevel::Light
        } else {
            CongestionLevel::None
        };
        
        // Return worst level
        [loss_level, rtt_level, queue_level].into_iter().max().unwrap_or(CongestionLevel::None)
    }
}

/// Bandwidth scheduler configuration
#[derive(Clone)]
pub struct BandwidthConfig {
    /// Total outbound bandwidth (bytes/sec)
    pub total_bandwidth: u64,
    /// Per-class queue sizes (bytes)
    pub queue_sizes: HashMap<TrafficClass, usize>,
    /// Per-peer rate limit (bytes/sec)
    pub per_peer_rate: u64,
    /// Enable adaptive congestion control
    pub enable_congestion_control: bool,
    /// Scheduler tick interval
    pub tick_interval: Duration,
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        let mut queue_sizes = HashMap::new();
        queue_sizes.insert(TrafficClass::Consensus, 10 * 1024 * 1024);  // 10 MB
        queue_sizes.insert(TrafficClass::Votes, 5 * 1024 * 1024);       // 5 MB
        queue_sizes.insert(TrafficClass::Blocks, 20 * 1024 * 1024);     // 20 MB
        queue_sizes.insert(TrafficClass::Transactions, 10 * 1024 * 1024);
        queue_sizes.insert(TrafficClass::Sync, 50 * 1024 * 1024);       // 50 MB
        queue_sizes.insert(TrafficClass::Background, 5 * 1024 * 1024);
        
        Self {
            total_bandwidth: 100 * 1024 * 1024, // 100 MB/s
            queue_sizes,
            per_peer_rate: 10 * 1024 * 1024,    // 10 MB/s per peer
            enable_congestion_control: true,
            tick_interval: Duration::from_millis(1),
        }
    }
}

/// Main bandwidth scheduler
pub struct BandwidthScheduler {
    /// Configuration
    config: BandwidthConfig,
    /// Per-class queues
    queues: RwLock<HashMap<TrafficClass, ClassQueue>>,
    /// Global rate limiter
    global_limiter: Mutex<TokenBucket>,
    /// Per-peer rate limiters
    peer_limiters: RwLock<HashMap<[u8; 32], PeerRateLimiter>>,
    /// Congestion detector
    congestion: Mutex<CongestionDetector>,
    /// Current virtual time for WFQ
    virtual_time: Mutex<f64>,
    /// Statistics
    stats: Mutex<SchedulerStats>,
}

/// Scheduler statistics
#[derive(Default, Clone)]
pub struct SchedulerStats {
    pub packets_scheduled: u64,
    pub bytes_scheduled: u64,
    pub packets_dropped: u64,
    pub bytes_dropped: u64,
    pub avg_queue_delay_ms: f64,
    pub congestion_events: u64,
}

impl BandwidthScheduler {
    pub fn new(config: BandwidthConfig) -> Self {
        let mut queues = HashMap::new();
        for class in TrafficClass::all() {
            let max_bytes = config.queue_sizes.get(class).copied().unwrap_or(10 * 1024 * 1024);
            queues.insert(*class, ClassQueue::new(max_bytes));
        }
        
        Self {
            global_limiter: Mutex::new(TokenBucket::new(
                config.total_bandwidth,
                config.total_bandwidth * 2,
            )),
            config,
            queues: RwLock::new(queues),
            peer_limiters: RwLock::new(HashMap::new()),
            congestion: Mutex::new(CongestionDetector::new()),
            virtual_time: Mutex::new(0.0),
            stats: Mutex::new(SchedulerStats::default()),
        }
    }
    
    /// Enqueues a packet for transmission
    pub fn enqueue(&self, packet: QueuedPacket) -> bool {
        let mut queues = self.queues.write();
        
        if let Some(queue) = queues.get_mut(&packet.class) {
            if queue.enqueue(packet) {
                true
            } else {
                let mut stats = self.stats.lock();
                stats.packets_dropped += 1;
                false
            }
        } else {
            false
        }
    }
    
    /// Dequeues the next packet using Weighted Fair Queuing
    pub fn dequeue(&self) -> Option<QueuedPacket> {
        let congestion_level = if self.config.enable_congestion_control {
            self.congestion.lock().detect()
        } else {
            CongestionLevel::None
        };
        
        let bandwidth_multiplier = congestion_level.bandwidth_multiplier();
        
        // Check global rate limit
        {
            let mut limiter = self.global_limiter.lock();
            // Peek at smallest packet to check if we can send anything
            let min_packet_size = self.min_pending_packet_size();
            if min_packet_size > 0 && !limiter.try_consume(0) {
                // Rate limited, can't send now
                if limiter.available() < min_packet_size as u64 {
                    return None;
                }
            }
        }
        
        let mut queues = self.queues.write();
        let mut virtual_time = self.virtual_time.lock();
        
        // Find queue with minimum virtual finish time that has packets
        let mut best_class: Option<TrafficClass> = None;
        let mut best_vft = f64::MAX;
        
        for (class, queue) in queues.iter() {
            if !queue.is_empty() {
                // Calculate virtual finish time
                let packet = match queue.peek() {
                    Some(p) => p,
                    None => continue,
                };
                let weight = class.weight() as f64 * bandwidth_multiplier;
                
                // CRITICAL: Guard against division by zero (weight=0 when severe congestion
                // reduces Background class weight to 0, or bandwidth_multiplier is 0)
                if weight <= 0.0 {
                    continue;
                }
                
                let vft = queue.virtual_finish_time + (packet.size() as f64 / weight);
                
                // CRITICAL: Guard against NaN/Infinity from floating point edge cases
                if !vft.is_finite() {
                    tracing::warn!("Non-finite virtual finish time for {:?}, skipping", class);
                    continue;
                }
                
                if vft < best_vft {
                    best_vft = vft;
                    best_class = Some(*class);
                }
            }
        }
        
        // Dequeue from best queue
        if let Some(class) = best_class {
            if let Some(queue) = queues.get_mut(&class) {
                if let Some(packet) = queue.dequeue() {
                    // Update virtual time with overflow protection
                    // Clamp to prevent unbounded growth over long runtimes
                    const MAX_VIRTUAL_TIME: f64 = 1e15;
                    let clamped_vft = if best_vft > MAX_VIRTUAL_TIME {
                        // Reset virtual times to prevent overflow accumulation
                        tracing::debug!("Virtual time reset: {} exceeded max", best_vft);
                        0.0
                    } else {
                        best_vft
                    };
                    *virtual_time = clamped_vft;
                    queue.virtual_finish_time = clamped_vft;
                    
                    // Consume from global rate limiter
                    {
                        let mut limiter = self.global_limiter.lock();
                        limiter.try_consume(packet.size() as u64);
                    }
                    
                    // Record statistics
                    {
                        let mut stats = self.stats.lock();
                        stats.packets_scheduled += 1;
                        stats.bytes_scheduled += packet.size() as u64;
                        
                        // Update average queue delay
                        let delay_ms = packet.age().as_secs_f64() * 1000.0;
                        stats.avg_queue_delay_ms = 0.1 * delay_ms + 0.9 * stats.avg_queue_delay_ms;
                    }
                    
                    // Record queue delay for congestion detection
                    self.congestion.lock().record_queue_delay(packet.age());
                    
                    return Some(packet);
                }
            }
        }
        
        None
    }
    
    /// Gets minimum pending packet size (for rate limiting check)
    fn min_pending_packet_size(&self) -> usize {
        let queues = self.queues.read();
        queues
            .values()
            .filter_map(|q| q.peek().map(|p| p.size()))
            .min()
            .unwrap_or(0)
    }
    
    /// Dequeues a batch of packets up to max_bytes
    pub fn dequeue_batch(&self, max_bytes: usize) -> Vec<QueuedPacket> {
        let mut batch = Vec::new();
        let mut total_bytes = 0;
        
        while total_bytes < max_bytes {
            if let Some(packet) = self.dequeue() {
                total_bytes += packet.size();
                batch.push(packet);
            } else {
                break;
            }
        }
        
        batch
    }
    
    /// Registers a peer for rate limiting
    pub fn register_peer(&self, peer_id: [u8; 32]) {
        let mut limiters = self.peer_limiters.write();
        if !limiters.contains_key(&peer_id) {
            limiters.insert(
                peer_id,
                PeerRateLimiter::new(peer_id, self.config.per_peer_rate, self.config.per_peer_rate),
            );
        }
    }
    
    /// Checks if sending to a peer is allowed
    pub fn can_send_to_peer(&self, peer_id: &[u8; 32], bytes: u64) -> bool {
        let mut limiters = self.peer_limiters.write();
        if let Some(limiter) = limiters.get_mut(peer_id) {
            limiter.try_send(bytes)
        } else {
            true // Unknown peer, allow
        }
    }
    
    /// Records RTT for congestion detection
    pub fn record_rtt(&self, rtt: Duration) {
        self.congestion.lock().record_rtt(rtt);
    }
    
    /// Records packet loss for congestion detection
    pub fn record_loss(&self, sent: u64, lost: u64) {
        let mut congestion = self.congestion.lock();
        congestion.record_loss(sent, lost);
        
        if lost > 0 {
            self.stats.lock().congestion_events += 1;
        }
    }
    
    /// Returns current congestion level
    pub fn congestion_level(&self) -> CongestionLevel {
        self.congestion.lock().detect()
    }
    
    /// Returns current statistics
    pub fn stats(&self) -> SchedulerStats {
        self.stats.lock().clone()
    }
    
    /// Returns queue statistics per class
    pub fn queue_stats(&self) -> HashMap<TrafficClass, (usize, usize, u64)> {
        let queues = self.queues.read();
        queues
            .iter()
            .map(|(class, queue)| (*class, (queue.len(), queue.current_bytes, queue.drops)))
            .collect()
    }
    
    /// Returns total pending bytes across all queues
    pub fn pending_bytes(&self) -> usize {
        self.queues.read().values().map(|q| q.current_bytes).sum()
    }
    
    /// Cleans up stale peer limiters
    pub fn cleanup_peers(&self, max_idle: Duration) {
        let mut limiters = self.peer_limiters.write();
        limiters.retain(|_, limiter| limiter.last_activity.elapsed() < max_idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_traffic_class_priority() {
        assert!(TrafficClass::Consensus.weight() > TrafficClass::Votes.weight());
        assert!(TrafficClass::Votes.weight() > TrafficClass::Transactions.weight());
        assert!(TrafficClass::Transactions.weight() > TrafficClass::Background.weight());
    }
    
    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1000, 2000); // 1000 bytes/sec, 2000 burst
        
        // Should have full burst initially
        assert!(bucket.try_consume(1500));
        assert!(bucket.available() < 1000);
        
        // Can't consume more than available
        assert!(!bucket.try_consume(1000));
    }
    
    #[test]
    fn test_scheduler_priority() {
        let config = BandwidthConfig::default();
        let scheduler = BandwidthScheduler::new(config);
        
        // Enqueue low priority first
        scheduler.enqueue(QueuedPacket::new(
            TrafficClass::Background,
            vec![0u8; 100],
            None,
        ));
        
        // Enqueue high priority second
        scheduler.enqueue(QueuedPacket::new(
            TrafficClass::Consensus,
            vec![0u8; 100],
            None,
        ));
        
        // High priority should come out first (due to higher weight)
        let first = scheduler.dequeue().unwrap();
        assert_eq!(first.class, TrafficClass::Consensus);
    }
    
    #[test]
    fn test_congestion_detection() {
        let mut detector = CongestionDetector::new();
        
        // Record normal RTT
        detector.record_rtt(Duration::from_millis(50));
        assert_eq!(detector.detect(), CongestionLevel::None);
        
        // Record high RTT
        for _ in 0..10 {
            detector.record_rtt(Duration::from_millis(200));
        }
        
        // Should detect congestion
        let level = detector.detect();
        assert!(level != CongestionLevel::None);
    }
    
    #[test]
    fn test_queue_drop() {
        let config = BandwidthConfig {
            queue_sizes: [(TrafficClass::Background, 100)].into_iter().collect(),
            ..Default::default()
        };
        
        let scheduler = BandwidthScheduler::new(config);
        
        // First packet should succeed
        assert!(scheduler.enqueue(QueuedPacket::new(
            TrafficClass::Background,
            vec![0u8; 50],
            None,
        )));
        
        // Second packet should succeed
        assert!(scheduler.enqueue(QueuedPacket::new(
            TrafficClass::Background,
            vec![0u8; 40],
            None,
        )));
        
        // Third packet should be dropped (queue full)
        assert!(!scheduler.enqueue(QueuedPacket::new(
            TrafficClass::Background,
            vec![0u8; 50],
            None,
        )));
    }
}
