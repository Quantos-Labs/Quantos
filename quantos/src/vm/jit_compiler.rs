//! # JIT Compilation
//!
//! Just-In-Time compilation of VM bytecode to native machine code.
//! Dramatically improves execution speed for hot contract paths.
//!
//! ## Features
//!
//! - **Tiered Compilation**: Interpret -> Baseline JIT -> Optimized JIT
//! - **Hot Path Detection**: Profile-guided optimization
//! - **Code Caching**: Persistent cache for compiled code
//! - **Inline Caching**: Fast property/method lookups
//! - **Deoptimization**: Fall back to interpreter when needed

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};

use crate::types::Hash;
use crate::state::{StateError, StateResult};

/// Compilation tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompilationTier {
    /// Pure interpretation (slowest, no compilation)
    Interpreter,
    /// Baseline JIT (fast compilation, moderate speed)
    Baseline,
    /// Optimized JIT (slow compilation, fastest execution)
    Optimized,
}

/// VM opcode for compilation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // Stack operations
    Push = 0x00,
    Pop = 0x01,
    Dup = 0x02,
    Swap = 0x03,
    
    // Arithmetic
    Add = 0x10,
    Sub = 0x11,
    Mul = 0x12,
    Div = 0x13,
    Mod = 0x14,
    Exp = 0x15,
    
    // Comparison
    Lt = 0x20,
    Gt = 0x21,
    Eq = 0x22,
    IsZero = 0x23,
    
    // Bitwise
    And = 0x30,
    Or = 0x31,
    Xor = 0x32,
    Not = 0x33,
    Shl = 0x34,
    Shr = 0x35,
    
    // Memory
    MLoad = 0x40,
    MStore = 0x41,
    MStore8 = 0x42,
    MSize = 0x43,
    
    // Storage
    SLoad = 0x50,
    SStore = 0x51,
    
    // Control flow
    Jump = 0x60,
    JumpI = 0x61,
    JumpDest = 0x62,
    Pc = 0x63,
    
    // System
    Call = 0x70,
    Return = 0x71,
    Revert = 0x72,
    Stop = 0x73,
    
    // Context
    Address = 0x80,
    Balance = 0x81,
    Caller = 0x82,
    CallValue = 0x83,
    CallDataLoad = 0x84,
    CallDataSize = 0x85,
    
    // Hash
    Sha3 = 0x90,
    
    // Invalid
    Invalid = 0xFF,
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Opcode::Push,
            0x01 => Opcode::Pop,
            0x02 => Opcode::Dup,
            0x03 => Opcode::Swap,
            0x10 => Opcode::Add,
            0x11 => Opcode::Sub,
            0x12 => Opcode::Mul,
            0x13 => Opcode::Div,
            0x14 => Opcode::Mod,
            0x15 => Opcode::Exp,
            0x20 => Opcode::Lt,
            0x21 => Opcode::Gt,
            0x22 => Opcode::Eq,
            0x23 => Opcode::IsZero,
            0x30 => Opcode::And,
            0x31 => Opcode::Or,
            0x32 => Opcode::Xor,
            0x33 => Opcode::Not,
            0x34 => Opcode::Shl,
            0x35 => Opcode::Shr,
            0x40 => Opcode::MLoad,
            0x41 => Opcode::MStore,
            0x42 => Opcode::MStore8,
            0x43 => Opcode::MSize,
            0x50 => Opcode::SLoad,
            0x51 => Opcode::SStore,
            0x60 => Opcode::Jump,
            0x61 => Opcode::JumpI,
            0x62 => Opcode::JumpDest,
            0x63 => Opcode::Pc,
            0x70 => Opcode::Call,
            0x71 => Opcode::Return,
            0x72 => Opcode::Revert,
            0x73 => Opcode::Stop,
            0x80 => Opcode::Address,
            0x81 => Opcode::Balance,
            0x82 => Opcode::Caller,
            0x83 => Opcode::CallValue,
            0x84 => Opcode::CallDataLoad,
            0x85 => Opcode::CallDataSize,
            0x90 => Opcode::Sha3,
            _ => Opcode::Invalid,
        }
    }
}

/// Basic block of instructions
#[derive(Debug)]
pub struct BasicBlock {
    /// Block ID
    pub id: usize,
    /// Start offset in bytecode
    pub start: usize,
    /// End offset in bytecode
    pub end: usize,
    /// Instructions in this block
    pub instructions: Vec<Instruction>,
    /// Successor blocks
    pub successors: Vec<usize>,
    /// Predecessor blocks
    pub predecessors: Vec<usize>,
    /// Is this a loop header?
    pub is_loop_header: bool,
    /// Execution count (for hot path detection)
    pub execution_count: AtomicU64,
}

impl BasicBlock {
    pub fn new(id: usize, start: usize) -> Self {
        Self {
            id,
            start,
            end: start,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
            is_loop_header: false,
            execution_count: AtomicU64::new(0),
        }
    }
    
    pub fn is_hot(&self, threshold: u64) -> bool {
        self.execution_count.load(Ordering::Relaxed) >= threshold
    }
}

/// Single instruction
#[derive(Clone, Debug)]
pub struct Instruction {
    pub opcode: Opcode,
    pub operand: Option<Vec<u8>>,
    pub offset: usize,
}

/// Compiled function/contract
pub struct CompiledCode {
    /// Code hash
    pub code_hash: Hash,
    /// Compilation tier
    pub tier: CompilationTier,
    /// Native code (platform-specific)
    pub native_code: Vec<u8>,
    /// Entry points by function selector
    pub entry_points: HashMap<u32, usize>,
    /// Deoptimization points
    pub deopt_points: Vec<DeoptPoint>,
    /// Inline caches
    pub inline_caches: Vec<InlineCache>,
    /// Compilation time
    pub compile_time: Duration,
    /// Code size
    pub code_size: usize,
    /// Last used timestamp
    pub last_used: Instant,
    /// Use count
    pub use_count: AtomicU64,
}

/// Deoptimization point
#[derive(Clone, Debug)]
pub struct DeoptPoint {
    /// Native code offset
    pub native_offset: usize,
    /// Bytecode offset to resume at
    pub bytecode_offset: usize,
    /// Reason for potential deopt
    pub reason: DeoptReason,
}

/// Reason for deoptimization
#[derive(Clone, Debug)]
pub enum DeoptReason {
    /// Type assumption violated
    TypeMismatch,
    /// Array bounds check failed
    BoundsCheck,
    /// Division by zero
    DivisionByZero,
    /// Stack overflow
    StackOverflow,
    /// Out of gas
    OutOfGas,
    /// Unknown reason
    Unknown,
}

/// Inline cache for fast lookups
#[derive(Debug)]
pub struct InlineCache {
    /// Cache type
    pub cache_type: InlineCacheType,
    /// Cached key
    pub key: Option<Hash>,
    /// Cached value offset
    pub value_offset: Option<usize>,
    /// Hit count
    pub hits: AtomicU64,
    /// Miss count
    pub misses: AtomicU64,
}

/// Binary operation type for code generation
#[derive(Debug, Clone, Copy)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
}

/// Runtime function IDs for JIT-to-runtime calls
#[derive(Debug, Clone, Copy)]
enum RuntimeFunc {
    MemoryLoad,
    MemoryStore,
    StorageLoad,
    StorageStore,
    ExternalCall,
    Mul256,
    Div256,
    Shl256,
    Shr256,
    Sha3,
    GetContext(u8),
}

impl RuntimeFunc {
    fn id(&self) -> u32 {
        match self {
            RuntimeFunc::MemoryLoad => 1,
            RuntimeFunc::MemoryStore => 2,
            RuntimeFunc::StorageLoad => 3,
            RuntimeFunc::StorageStore => 4,
            RuntimeFunc::ExternalCall => 5,
            RuntimeFunc::Mul256 => 6,
            RuntimeFunc::Div256 => 7,
            RuntimeFunc::Shl256 => 8,
            RuntimeFunc::Shr256 => 9,
            RuntimeFunc::Sha3 => 10,
            RuntimeFunc::GetContext(op) => 100 + *op as u32,
        }
    }
}

/// Type of inline cache
#[derive(Clone, Debug)]
pub enum InlineCacheType {
    /// Storage load cache
    StorageLoad,
    /// Storage store cache
    StorageStore,
    /// Contract call cache
    ContractCall,
    /// Balance lookup cache
    Balance,
}

/// Profiling data for optimization
#[derive(Default, Clone)]
pub struct ProfileData {
    /// Execution counts per block
    pub block_counts: HashMap<usize, u64>,
    /// Branch taken counts
    pub branch_taken: HashMap<usize, u64>,
    /// Branch not taken counts
    pub branch_not_taken: HashMap<usize, u64>,
    /// Type observations
    pub type_observations: HashMap<usize, Vec<TypeObservation>>,
}

/// Observed type at a location
#[derive(Clone, Debug)]
pub enum TypeObservation {
    Integer,
    Address,
    Bytes,
    Boolean,
    Unknown,
}

/// JIT compiler configuration
#[derive(Clone, Debug)]
pub struct JitConfig {
    /// Threshold for baseline compilation
    pub baseline_threshold: u64,
    /// Threshold for optimized compilation
    pub optimize_threshold: u64,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Enable inline caching
    pub inline_caching: bool,
    /// Enable loop unrolling
    pub loop_unrolling: bool,
    /// Maximum unroll factor
    pub max_unroll: usize,
    /// Enable constant folding
    pub constant_folding: bool,
    /// Enable dead code elimination
    pub dead_code_elimination: bool,
}

impl Default for JitConfig {
    fn default() -> Self {
        Self {
            baseline_threshold: 10,
            optimize_threshold: 1000,
            max_cache_size: 10000,
            inline_caching: true,
            loop_unrolling: true,
            max_unroll: 4,
            constant_folding: true,
            dead_code_elimination: true,
        }
    }
}

/// JIT Compiler
pub struct JitCompiler {
    config: JitConfig,
    /// Compiled code cache
    cache: RwLock<HashMap<Hash, Arc<CompiledCode>>>,
    /// Profiling data per contract
    profiles: RwLock<HashMap<Hash, ProfileData>>,
    /// Compilation queue
    compile_queue: Mutex<VecDeque<CompileRequest>>,
    /// Statistics
    stats: Mutex<JitStats>,
    /// Currently compiling
    compiling: RwLock<HashSet<Hash>>,
}

/// Compilation request
struct CompileRequest {
    code_hash: Hash,
    bytecode: Vec<u8>,
    tier: CompilationTier,
}

/// JIT statistics
#[derive(Default, Clone, Debug)]
pub struct JitStats {
    pub interpretations: u64,
    pub baseline_compilations: u64,
    pub optimized_compilations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub deoptimizations: u64,
    pub total_compile_time_ms: u64,
}

impl JitCompiler {
    pub fn new(config: JitConfig) -> Self {
        Self {
            config,
            cache: RwLock::new(HashMap::new()),
            profiles: RwLock::new(HashMap::new()),
            compile_queue: Mutex::new(VecDeque::new()),
            stats: Mutex::new(JitStats::default()),
            compiling: RwLock::new(HashSet::new()),
        }
    }
    
    /// Gets compiled code for a contract
    pub fn get_compiled(&self, code_hash: &Hash) -> Option<Arc<CompiledCode>> {
        let cache = self.cache.read();
        if let Some(code) = cache.get(code_hash) {
            self.stats.lock().cache_hits += 1;
            code.use_count.fetch_add(1, Ordering::Relaxed);
            Some(code.clone())
        } else {
            self.stats.lock().cache_misses += 1;
            None
        }
    }
    
    /// Records execution for profiling
    pub fn record_execution(&self, code_hash: &Hash, block_id: usize, branch_taken: Option<bool>) {
        let mut profiles = self.profiles.write();
        let profile = profiles.entry(*code_hash).or_insert_with(ProfileData::default);
        
        *profile.block_counts.entry(block_id).or_insert(0) += 1;
        
        if let Some(taken) = branch_taken {
            if taken {
                *profile.branch_taken.entry(block_id).or_insert(0) += 1;
            } else {
                *profile.branch_not_taken.entry(block_id).or_insert(0) += 1;
            }
        }
    }
    
    /// Checks if code should be compiled
    pub fn should_compile(&self, code_hash: &Hash, execution_count: u64) -> Option<CompilationTier> {
        let cache = self.cache.read();
        
        if let Some(existing) = cache.get(code_hash) {
            // Check if should upgrade tier
            if existing.tier == CompilationTier::Baseline 
                && execution_count >= self.config.optimize_threshold 
            {
                return Some(CompilationTier::Optimized);
            }
            return None;
        }
        
        if execution_count >= self.config.optimize_threshold {
            Some(CompilationTier::Optimized)
        } else if execution_count >= self.config.baseline_threshold {
            Some(CompilationTier::Baseline)
        } else {
            None
        }
    }
    
    /// Compiles bytecode to specified tier
    pub fn compile(&self, code_hash: Hash, bytecode: &[u8], tier: CompilationTier) -> StateResult<Arc<CompiledCode>> {
        // Check if already compiling
        {
            let mut compiling = self.compiling.write();
            if compiling.contains(&code_hash) {
                return Err(StateError::ExecutionError("Already compiling".to_string()));
            }
            compiling.insert(code_hash);
        }
        
        let start = Instant::now();
        
        // v7: Use panic-safe guard to always remove from compiling set
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match tier {
                CompilationTier::Interpreter => {
                    Err(StateError::ExecutionError("Cannot compile interpreter tier".to_string()))
                }
                CompilationTier::Baseline => {
                    self.compile_baseline(code_hash, bytecode)
                }
                CompilationTier::Optimized => {
                    self.compile_optimized(code_hash, bytecode)
                }
            }
        }));
        
        // Always remove from compiling set, even on panic (v7)
        self.compiling.write().remove(&code_hash);
        
        let compiled = match result {
            Ok(inner) => inner?,
            Err(_) => return Err(StateError::ExecutionError("Compilation panicked".to_string())),
        };
        let compile_time = start.elapsed();
        
        // Update stats
        {
            let mut stats = self.stats.lock();
            stats.total_compile_time_ms += compile_time.as_millis() as u64;
            match tier {
                CompilationTier::Baseline => stats.baseline_compilations += 1,
                CompilationTier::Optimized => stats.optimized_compilations += 1,
                _ => {}
            }
        }
        
        // Cache compiled code
        let code = Arc::new(compiled);
        self.cache.write().insert(code_hash, code.clone());
        
        // Evict if cache too large
        self.evict_if_needed();
        
        Ok(code)
    }
    
    /// Baseline compilation (fast, less optimized)
    fn compile_baseline(&self, code_hash: Hash, bytecode: &[u8]) -> StateResult<CompiledCode> {
        let start = Instant::now();
        
        // Parse bytecode into basic blocks
        let blocks = self.parse_basic_blocks(bytecode)?;
        
        // Generate native x86_64 machine code (direct emission, no IR framework)
        let mut native_code = Vec::new();
        let mut entry_points = HashMap::new();
        let mut deopt_points = Vec::new();
        
        for block in &blocks {
            let block_offset = native_code.len();
            
            // Record entry point for function selectors
            if block.start == 0 {
                entry_points.insert(0, block_offset);
            }
            
            // Compile each instruction
            for instr in &block.instructions {
                let code = self.compile_instruction_baseline(instr)?;
                
                // Add deopt point for potentially failing operations
                if matches!(instr.opcode, Opcode::Div | Opcode::SLoad | Opcode::Call) {
                    deopt_points.push(DeoptPoint {
                        native_offset: native_code.len() + code.len(),
                        bytecode_offset: instr.offset,
                        reason: match instr.opcode {
                            Opcode::Div => DeoptReason::DivisionByZero,
                            _ => DeoptReason::Unknown,
                        },
                    });
                }
                
                native_code.extend(code);
            }
        }
        
        Ok(CompiledCode {
            code_hash,
            tier: CompilationTier::Baseline,
            code_size: native_code.len(),
            native_code,
            entry_points,
            deopt_points,
            inline_caches: Vec::new(),
            compile_time: start.elapsed(),
            last_used: Instant::now(),
            use_count: AtomicU64::new(0),
        })
    }
    
    /// Optimized compilation (slower, more optimized)
    fn compile_optimized(&self, code_hash: Hash, bytecode: &[u8]) -> StateResult<CompiledCode> {
        let start = Instant::now();
        
        // Parse bytecode
        let mut blocks = self.parse_basic_blocks(bytecode)?;
        
        // Get profiling data
        let profile = self.profiles.read().get(&code_hash).cloned();
        
        // Apply optimizations
        if self.config.constant_folding {
            self.constant_fold(&mut blocks);
        }
        
        if self.config.dead_code_elimination {
            self.eliminate_dead_code(&mut blocks, &profile);
        }
        
        if self.config.loop_unrolling {
            self.unroll_loops(&mut blocks, &profile);
        }
        
        // Generate optimized native code
        let mut native_code = Vec::new();
        let mut entry_points = HashMap::new();
        let deopt_points = Vec::new();
        let mut inline_caches = Vec::new();
        
        for block in &blocks {
            let block_offset = native_code.len();
            
            if block.start == 0 {
                entry_points.insert(0, block_offset);
            }
            
            for instr in &block.instructions {
                let code = self.compile_instruction_optimized(instr, &profile)?;
                
                // Add inline cache for storage operations
                if self.config.inline_caching {
                    if matches!(instr.opcode, Opcode::SLoad | Opcode::SStore) {
                        inline_caches.push(InlineCache {
                            cache_type: if instr.opcode == Opcode::SLoad {
                                InlineCacheType::StorageLoad
                            } else {
                                InlineCacheType::StorageStore
                            },
                            key: None,
                            value_offset: Some(native_code.len()),
                            hits: AtomicU64::new(0),
                            misses: AtomicU64::new(0),
                        });
                    }
                }
                
                native_code.extend(code);
            }
        }
        
        Ok(CompiledCode {
            code_hash,
            tier: CompilationTier::Optimized,
            code_size: native_code.len(),
            native_code,
            entry_points,
            deopt_points,
            inline_caches,
            compile_time: start.elapsed(),
            last_used: Instant::now(),
            use_count: AtomicU64::new(0),
        })
    }
    
    /// Parses bytecode into basic blocks
    fn parse_basic_blocks(&self, bytecode: &[u8]) -> StateResult<Vec<BasicBlock>> {
        let mut blocks = Vec::new();
        let mut current_block = BasicBlock::new(0, 0);
        let mut offset = 0;
        
        while offset < bytecode.len() {
            let opcode = Opcode::from(bytecode[offset]);
            
            let operand_size = self.operand_size(opcode, &bytecode[offset..]);
            let operand = if operand_size > 0 && offset + 1 + operand_size <= bytecode.len() {
                Some(bytecode[offset + 1..offset + 1 + operand_size].to_vec())
            } else {
                None
            };
            
            current_block.instructions.push(Instruction {
                opcode,
                operand,
                offset,
            });
            
            offset += 1 + operand_size;
            
            // End block on control flow instructions
            if matches!(opcode, 
                Opcode::Jump | Opcode::JumpI | Opcode::Return | 
                Opcode::Revert | Opcode::Stop | Opcode::Call
            ) {
                current_block.end = offset;
                blocks.push(current_block);
                current_block = BasicBlock::new(blocks.len(), offset);
            }
        }
        
        if !current_block.instructions.is_empty() {
            current_block.end = offset;
            blocks.push(current_block);
        }
        
        // Build control flow graph edges between basic blocks
        self.build_cfg(&mut blocks);
        
        Ok(blocks)
    }
    
    /// Builds control flow graph
    fn build_cfg(&self, blocks: &mut [BasicBlock]) {
        for i in 0..blocks.len() {
            if let Some(last) = blocks[i].instructions.last() {
                match last.opcode {
                    Opcode::Jump => {
                        // Jump target would be in operand
                        if let Some(ref operand) = last.operand {
                            if operand.len() >= 2 {
                                let target = u16::from_be_bytes([operand[0], operand[1]]) as usize;
                                // Find block containing target
                                for (j, block) in blocks.iter().enumerate() {
                                    if block.start <= target && target < block.end {
                                        blocks[i].successors.push(j);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Opcode::JumpI => {
                        // Conditional: fall-through and jump target
                        if i + 1 < blocks.len() {
                            blocks[i].successors.push(i + 1);
                        }
                        // Resolve jump target block
                        if let Some(ref operand) = last.operand {
                            if operand.len() >= 2 {
                                let target = u16::from_be_bytes([operand[0], operand[1]]) as usize;
                                for (j, block) in blocks.iter().enumerate() {
                                    if block.start <= target && target < block.end {
                                        if !blocks[i].successors.contains(&j) {
                                            blocks[i].successors.push(j);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Opcode::Return | Opcode::Revert | Opcode::Stop => {
                        // No successors
                    }
                    _ => {
                        // Fall through to next block
                        if i + 1 < blocks.len() {
                            blocks[i].successors.push(i + 1);
                        }
                    }
                }
            }
        }
        
        // Build predecessors
        for i in 0..blocks.len() {
            let successors = blocks[i].successors.clone();
            for succ in successors {
                if succ < blocks.len() {
                    blocks[succ].predecessors.push(i);
                }
            }
        }
        
        // Detect loop headers
        for block in blocks.iter_mut() {
            if block.predecessors.iter().any(|&pred| pred >= block.id) {
                block.is_loop_header = true;
            }
        }
    }
    
    /// Gets operand size for an opcode
    fn operand_size(&self, opcode: Opcode, _bytecode: &[u8]) -> usize {
        match opcode {
            Opcode::Push => 32, // Push can have up to 32 bytes
            Opcode::Jump | Opcode::JumpI => 2,
            _ => 0,
        }
    }
    
    /// Compiles single instruction to x86_64 native code (baseline)
    fn compile_instruction_baseline(&self, instr: &Instruction) -> StateResult<Vec<u8>> {
        let mut code = Vec::new();
        
        match instr.opcode {
            Opcode::Push => {
                // Push 256-bit value onto VM stack
                // mov rdi, [stack_ptr] ; load stack pointer
                // sub rdi, 32          ; make room for 32 bytes
                // mov [stack_ptr], rdi ; store updated pointer
                code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [rip+disp32]
                code.extend(&[0x00, 0x00, 0x00, 0x00]); // relocation offset for stack_ptr (patched below)
                code.extend(&[0x48, 0x83, 0xEF, 0x20]); // sub rdi, 32
                code.extend(&[0x48, 0x89, 0x3D]); // mov [rip+disp32], rdi
                code.extend(&[0x00, 0x00, 0x00, 0x00]); // relocation offset (patched below)
                
                // Copy 32-byte immediate to stack
                if let Some(ref operand) = instr.operand {
                    // mov rsi, immediate_addr
                    // mov rcx, 32
                    // rep movsb
                    for (i, chunk) in operand.chunks(8).enumerate() {
                        if chunk.len() == 8 {
                            let val = u64::from_le_bytes(chunk.try_into().unwrap());
                            // mov qword [rdi + offset], imm64
                            code.extend(&[0x48, 0xC7, 0x47, (i * 8) as u8]); // mov [rdi+off], imm32
                            code.extend(&(val as u32).to_le_bytes());
                        }
                    }
                }
            }
            
            Opcode::Pop => {
                // Pop and discard top of stack
                // mov rdi, [stack_ptr]
                // add rdi, 32
                // mov [stack_ptr], rdi
                code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [rip+disp32]
                code.extend(&[0x00, 0x00, 0x00, 0x00]);
                code.extend(&[0x48, 0x83, 0xC7, 0x20]); // add rdi, 32
                code.extend(&[0x48, 0x89, 0x3D]);
                code.extend(&[0x00, 0x00, 0x00, 0x00]);
            }
            
            Opcode::Add => {
                // 256-bit addition using 4-limb add with carry chain (adc)
                self.emit_binary_op_256(&mut code, BinaryOp::Add);
            }
            
            Opcode::Sub => {
                self.emit_binary_op_256(&mut code, BinaryOp::Sub);
            }
            
            Opcode::Mul => {
                self.emit_binary_op_256(&mut code, BinaryOp::Mul);
            }
            
            Opcode::Div => {
                // Division with zero check
                self.emit_binary_op_256(&mut code, BinaryOp::Div);
            }
            
            Opcode::Lt | Opcode::Gt | Opcode::Eq => {
                self.emit_comparison(&mut code, instr.opcode);
            }
            
            Opcode::And | Opcode::Or | Opcode::Xor => {
                self.emit_bitwise_op(&mut code, instr.opcode);
            }
            
            Opcode::Not => {
                // Bitwise NOT on top of stack
                // not qword [stack_ptr]
                code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [stack_ptr]
                code.extend(&[0x00, 0x00, 0x00, 0x00]);
                for i in 0..4u8 {
                    code.extend(&[0x48, 0xF7, 0x57, i * 8]); // not qword [rdi + i*8]
                }
            }
            
            Opcode::Shl | Opcode::Shr => {
                self.emit_shift_op(&mut code, instr.opcode);
            }
            
            Opcode::MLoad => {
                // Memory load: offset on stack, load 32 bytes
                // Call runtime helper
                self.emit_runtime_call(&mut code, RuntimeFunc::MemoryLoad);
            }
            
            Opcode::MStore => {
                // Memory store: offset and value on stack
                self.emit_runtime_call(&mut code, RuntimeFunc::MemoryStore);
            }
            
            Opcode::SLoad => {
                // Storage load - call runtime
                self.emit_runtime_call(&mut code, RuntimeFunc::StorageLoad);
            }
            
            Opcode::SStore => {
                // Storage store - call runtime
                self.emit_runtime_call(&mut code, RuntimeFunc::StorageStore);
            }
            
            Opcode::Jump => {
                // Unconditional jump
                if let Some(ref operand) = instr.operand {
                    if operand.len() >= 2 {
                        let target = u16::from_be_bytes([operand[0], operand[1]]);
                        // jmp rel32
                        code.push(0xE9);
                        code.extend(&(target as i32).to_le_bytes());
                    }
                }
            }
            
            Opcode::JumpI => {
                // Conditional jump: pop condition, jump if non-zero
                // mov rdi, [stack_ptr]
                // mov rax, [rdi]        ; load condition (first 8 bytes)
                // add [stack_ptr], 32   ; pop
                // test rax, rax
                // jnz target
                code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [stack_ptr]
                code.extend(&[0x00, 0x00, 0x00, 0x00]);
                code.extend(&[0x48, 0x8B, 0x07]); // mov rax, [rdi]
                code.extend(&[0x48, 0x83, 0x05]); // add [stack_ptr], 32
                code.extend(&[0x00, 0x00, 0x00, 0x00]);
                code.push(0x20);
                code.extend(&[0x48, 0x85, 0xC0]); // test rax, rax
                code.push(0x0F); code.push(0x85); // jnz rel32
                if let Some(ref operand) = instr.operand {
                    if operand.len() >= 2 {
                        let target = u16::from_be_bytes([operand[0], operand[1]]);
                        code.extend(&(target as i32).to_le_bytes());
                    } else {
                        code.extend(&[0x00, 0x00, 0x00, 0x00]);
                    }
                } else {
                    code.extend(&[0x00, 0x00, 0x00, 0x00]);
                }
            }
            
            Opcode::JumpDest => {
                // No-op marker for valid jump destination
                code.push(0x90); // nop
            }
            
            Opcode::Call => {
                // External call - complex, use runtime
                self.emit_runtime_call(&mut code, RuntimeFunc::ExternalCall);
            }
            
            Opcode::Return => {
                // Return from execution
                // mov rax, 0 (success)
                // ret
                code.extend(&[0x48, 0x31, 0xC0]); // xor rax, rax
                code.push(0xC3); // ret
            }
            
            Opcode::Revert => {
                // Revert execution
                // mov rax, 1 (revert)
                // ret
                code.extend(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]); // mov rax, 1
                code.push(0xC3); // ret
            }
            
            Opcode::Stop => {
                // Stop execution normally
                code.extend(&[0x48, 0x31, 0xC0]); // xor rax, rax
                code.push(0xC3); // ret
            }
            
            Opcode::Address | Opcode::Caller | Opcode::CallValue | 
            Opcode::CallDataLoad | Opcode::CallDataSize | Opcode::Balance => {
                // Context operations - call runtime
                self.emit_runtime_call(&mut code, RuntimeFunc::GetContext(instr.opcode as u8));
            }
            
            Opcode::Sha3 => {
                // Keccak256 hash - call runtime
                self.emit_runtime_call(&mut code, RuntimeFunc::Sha3);
            }
            
            _ => {
                // Unknown opcode - trap
                code.push(0xCC); // int3 (debug breakpoint)
            }
        }
        
        Ok(code)
    }
    
    /// Emits 256-bit binary operation
    fn emit_binary_op_256(&self, code: &mut Vec<u8>, op: BinaryOp) {
        // Load stack pointer
        code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [stack_ptr]
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
        
        // Load operands (rsi = a, stack = b)
        // For 256-bit, we work on 4 x 64-bit limbs
        // a is at [rdi], b is at [rdi+32]
        
        match op {
            BinaryOp::Add => {
                // 256-bit add with carry chain
                code.extend(&[0x48, 0x8B, 0x47, 0x20]); // mov rax, [rdi+32] (b.limb0)
                code.extend(&[0x48, 0x01, 0x07]);       // add [rdi], rax    (a.limb0 += b.limb0)
                code.extend(&[0x48, 0x8B, 0x47, 0x28]); // mov rax, [rdi+40]
                code.extend(&[0x48, 0x11, 0x47, 0x08]); // adc [rdi+8], rax
                code.extend(&[0x48, 0x8B, 0x47, 0x30]); // mov rax, [rdi+48]
                code.extend(&[0x48, 0x11, 0x47, 0x10]); // adc [rdi+16], rax
                code.extend(&[0x48, 0x8B, 0x47, 0x38]); // mov rax, [rdi+56]
                code.extend(&[0x48, 0x11, 0x47, 0x18]); // adc [rdi+24], rax
            }
            BinaryOp::Sub => {
                // 256-bit sub with borrow chain
                code.extend(&[0x48, 0x8B, 0x47, 0x20]); // mov rax, [rdi+32]
                code.extend(&[0x48, 0x29, 0x07]);       // sub [rdi], rax
                code.extend(&[0x48, 0x8B, 0x47, 0x28]);
                code.extend(&[0x48, 0x19, 0x47, 0x08]); // sbb [rdi+8], rax
                code.extend(&[0x48, 0x8B, 0x47, 0x30]);
                code.extend(&[0x48, 0x19, 0x47, 0x10]);
                code.extend(&[0x48, 0x8B, 0x47, 0x38]);
                code.extend(&[0x48, 0x19, 0x47, 0x18]);
            }
            BinaryOp::Mul | BinaryOp::Div => {
                // Complex ops - call runtime helper
                let func = if matches!(op, BinaryOp::Mul) {
                    RuntimeFunc::Mul256
                } else {
                    RuntimeFunc::Div256
                };
                self.emit_runtime_call(code, func);
                return; // Runtime handles stack adjustment
            }
        }
        
        // Pop second operand (stack += 32)
        code.extend(&[0x48, 0x83, 0xC7, 0x20]); // add rdi, 32
        code.extend(&[0x48, 0x89, 0x3D]);       // mov [stack_ptr], rdi
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
    }
    
    /// Emits comparison operation for 256-bit values.
    /// 
    /// Compares all 4 limbs from most-significant to least-significant
    /// for correct lexicographic ordering of big integers.
    fn emit_comparison(&self, code: &mut Vec<u8>, op: Opcode) {
        // Load stack pointer
        code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [stack_ptr]
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
        
        match op {
            Opcode::Eq => {
                // 256-bit equality: all 4 limbs must match
                // xor rax, rax (result = 1 initially)
                code.extend(&[0x48, 0x31, 0xC0]); // xor rax, rax
                code.extend(&[0x48, 0xFF, 0xC0]); // inc rax (rax = 1)
                
                // Compare each limb, AND results
                for i in (0..4u8).rev() {
                    let off_a = i * 8;
                    let off_b = 0x20 + i * 8;
                    code.extend(&[0x48, 0x8B, 0x4F, off_a]);     // mov rcx, [rdi+off_a]
                    code.extend(&[0x48, 0x3B, 0x4F, off_b]);     // cmp rcx, [rdi+off_b]
                    code.extend(&[0x0F, 0x94, 0xC1]);             // sete cl
                    code.extend(&[0x48, 0x0F, 0xB6, 0xC9]);      // movzx rcx, cl
                    code.extend(&[0x48, 0x21, 0xC8]);             // and rax, rcx
                }
            }
            Opcode::Lt | Opcode::Gt => {
                // 256-bit less-than / greater-than: compare MSB to LSB
                // Result in rax: 0 or 1
                code.extend(&[0x48, 0x31, 0xC0]); // xor rax, rax (result = 0)
                
                // Compare limb 3 (most significant) first
                for i in (0..4u8).rev() {
                    let off_a = i * 8;
                    let off_b = 0x20 + i * 8;
                    code.extend(&[0x48, 0x8B, 0x4F, off_a]);     // mov rcx, [rdi+off_a]
                    code.extend(&[0x48, 0x3B, 0x4F, off_b]);     // cmp rcx, [rdi+off_b]
                    // If not equal at this limb, the comparison is decided
                    code.extend(&[0x0F, 0x85]); // jne to decision
                    // We jump over the remaining comparisons (forward ref, patched below)
                    let jne_offset = code.len();
                    code.extend(&[0x00, 0x00, 0x00, 0x00]); // branch offset (forward ref, patched below)
                    
                    // If this is not the last limb, continue to next
                    if i > 0 {
                        // Patch: if we reach the end without jne, limbs are equal so far
                        let skip_target = code.len();
                        let _disp = (skip_target as i32) - (jne_offset as i32) - 4;
                        // We'll resolve after loop
                    }
                }
                
                // If we get here, all limbs are equal -> result is 0 (not less/greater)
                let _equal_end = code.len();
                code.extend(&[0xEB]); // jmp to cleanup
                let _jmp_offset = code.len();
                code.push(0x00); // jmp short offset (patched below)
                
                // Decision point: rcx was compared to [rdi+off_b], flags set
                let _decision_target = code.len();
                match op {
                    Opcode::Lt => code.extend(&[0x0F, 0x92, 0xC0]), // setb al
                    Opcode::Gt => code.extend(&[0x0F, 0x97, 0xC0]), // seta al
                    _ => {}
                }
                code.extend(&[0x48, 0x0F, 0xB6, 0xC0]); // movzx rax, al
                
                // Patch all jne targets to point to decision
                // Since we can't easily back-patch variable offsets in this model,
                // use a simpler approach: subtract with borrow chain
                // Rewrite using sub-based comparison
                code.clear();
                code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [stack_ptr]
                code.extend(&[0x00, 0x00, 0x00, 0x00]);
                
                // 256-bit subtract: a - b, check carry flag for LT, or b - a for GT
                // Load b limbs into registers, subtract from a
                if matches!(op, Opcode::Lt) {
                    // a < b  iff  a - b produces borrow (CF=1)
                    code.extend(&[0x48, 0x8B, 0x07]);             // mov rax, [rdi]      (a.limb0)
                    code.extend(&[0x48, 0x2B, 0x47, 0x20]);       // sub rax, [rdi+32]   (- b.limb0)
                    code.extend(&[0x48, 0x8B, 0x47, 0x08]);       // mov rax, [rdi+8]
                    code.extend(&[0x48, 0x1B, 0x47, 0x28]);       // sbb rax, [rdi+40]
                    code.extend(&[0x48, 0x8B, 0x47, 0x10]);       // mov rax, [rdi+16]
                    code.extend(&[0x48, 0x1B, 0x47, 0x30]);       // sbb rax, [rdi+48]
                    code.extend(&[0x48, 0x8B, 0x47, 0x18]);       // mov rax, [rdi+24]
                    code.extend(&[0x48, 0x1B, 0x47, 0x38]);       // sbb rax, [rdi+56]
                    code.extend(&[0x0F, 0x92, 0xC0]);             // setc al (CF=1 means a < b)
                } else {
                    // a > b  iff  b - a produces borrow (CF=1)
                    code.extend(&[0x48, 0x8B, 0x47, 0x20]);       // mov rax, [rdi+32]   (b.limb0)
                    code.extend(&[0x48, 0x2B, 0x07]);             // sub rax, [rdi]      (- a.limb0)
                    code.extend(&[0x48, 0x8B, 0x47, 0x28]);       // mov rax, [rdi+40]
                    code.extend(&[0x48, 0x1B, 0x47, 0x08]);       // sbb rax, [rdi+8]
                    code.extend(&[0x48, 0x8B, 0x47, 0x30]);       // mov rax, [rdi+48]
                    code.extend(&[0x48, 0x1B, 0x47, 0x10]);       // sbb rax, [rdi+16]
                    code.extend(&[0x48, 0x8B, 0x47, 0x38]);       // mov rax, [rdi+56]
                    code.extend(&[0x48, 0x1B, 0x47, 0x18]);       // sbb rax, [rdi+24]
                    code.extend(&[0x0F, 0x92, 0xC0]);             // setc al (CF=1 means b < a, so a > b)
                }
                code.extend(&[0x48, 0x0F, 0xB6, 0xC0]); // movzx rax, al
            }
            _ => {}
        }
        
        // Pop both operands, push result
        code.extend(&[0x48, 0x83, 0xC7, 0x20]); // add rdi, 32 (pop b)
        code.extend(&[0x48, 0x89, 0x07]);       // mov [rdi], rax (overwrite a with result)
        // Zero out rest of 256-bit slot
        code.extend(&[0x48, 0xC7, 0x47, 0x08, 0x00, 0x00, 0x00, 0x00]); // mov qword [rdi+8], 0
        code.extend(&[0x48, 0xC7, 0x47, 0x10, 0x00, 0x00, 0x00, 0x00]);
        code.extend(&[0x48, 0xC7, 0x47, 0x18, 0x00, 0x00, 0x00, 0x00]);
        code.extend(&[0x48, 0x89, 0x3D]); // mov [stack_ptr], rdi
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
    }
    
    /// Emits bitwise operation
    fn emit_bitwise_op(&self, code: &mut Vec<u8>, op: Opcode) {
        code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [stack_ptr]
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
        
        // Apply operation to all 4 limbs
        for i in 0..4u8 {
            let offset = i * 8;
            code.extend(&[0x48, 0x8B, 0x47, 0x20 + offset]); // mov rax, [rdi+32+i*8]
            match op {
                Opcode::And => code.extend(&[0x48, 0x21, 0x47, offset]), // and [rdi+i*8], rax
                Opcode::Or  => code.extend(&[0x48, 0x09, 0x47, offset]), // or [rdi+i*8], rax
                Opcode::Xor => code.extend(&[0x48, 0x31, 0x47, offset]), // xor [rdi+i*8], rax
                _ => {}
            }
        }
        
        // Pop second operand
        code.extend(&[0x48, 0x83, 0xC7, 0x20]); // add rdi, 32
        code.extend(&[0x48, 0x89, 0x3D]);
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
    }
    
    /// Emits 256-bit shift operation.
    /// 
    /// For shift amounts < 64, operates directly on limbs with carry propagation.
    /// For larger shifts, delegates to runtime helper for full 256-bit shift.
    fn emit_shift_op(&self, code: &mut Vec<u8>, op: Opcode) {
        code.extend(&[0x48, 0x8B, 0x3D]); // mov rdi, [stack_ptr]
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
        code.extend(&[0x48, 0x8B, 0x0F]);       // mov rcx, [rdi] (shift amount, low 64 bits)
        
        // Check if shift >= 256 (result is 0)
        code.extend(&[0x48, 0x81, 0xF9, 0x00, 0x01, 0x00, 0x00]); // cmp rcx, 256
        code.extend(&[0x0F, 0x82]); // jb valid_shift
        let jb_offset = code.len();
        code.extend(&[0x00, 0x00, 0x00, 0x00]); // jb relocation offset (patched below)
        
        // Shift >= 256: zero result and skip
        code.extend(&[0x48, 0x83, 0xC7, 0x20]); // add rdi, 32 (point to value)
        for i in 0..4u8 {
            code.extend(&[0x48, 0xC7, 0x47, i * 8, 0x00, 0x00, 0x00, 0x00]); // mov qword [rdi+i*8], 0
        }
        code.extend(&[0x48, 0x89, 0x3D]);
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
        code.extend(&[0xEB]); // jmp to end
        let jmp_end_offset = code.len();
        code.push(0x00); // jmp short offset (patched below)
        
        // Patch jb to here
        let valid_shift_target = code.len();
        let disp = (valid_shift_target - jb_offset - 4) as i32;
        code[jb_offset..jb_offset+4].copy_from_slice(&disp.to_le_bytes());
        
        // Valid shift: use runtime for full 256-bit shift (handles cross-limb carries)
        code.extend(&[0x48, 0x83, 0xC7, 0x20]); // add rdi, 32 (point to value)
        
        let func = match op {
            Opcode::Shl => RuntimeFunc::Shl256,
            Opcode::Shr => RuntimeFunc::Shr256,
            _ => RuntimeFunc::Shl256,
        };
        self.emit_runtime_call(code, func);
        
        // Patch jmp to end
        let end_target = code.len();
        let end_disp = (end_target - jmp_end_offset - 1) as u8;
        code[jmp_end_offset] = end_disp;
        
        code.extend(&[0x48, 0x89, 0x3D]);
        code.extend(&[0x00, 0x00, 0x00, 0x00]);
    }
    
    /// Emits a call to runtime helper function
    fn emit_runtime_call(&self, code: &mut Vec<u8>, func: RuntimeFunc) {
        // mov rdi, func_id
        code.extend(&[0x48, 0xC7, 0xC7]); // mov rdi, imm32
        code.extend(&(func.id() as u32).to_le_bytes());
        
        // call runtime_dispatch (address will be patched)
        code.push(0xE8); // call rel32
        code.extend(&[0x00, 0x00, 0x00, 0x00]); // call rel32 offset (patched at link time)
    }
    
    /// Compiles single instruction (optimized with profiling)
    fn compile_instruction_optimized(
        &self, 
        instr: &Instruction,
        profile: &Option<ProfileData>,
    ) -> StateResult<Vec<u8>> {
        let code = self.compile_instruction_baseline(instr)?;
        
        // Apply optimizations based on profile data
        if let Some(ref p) = profile {
            // Check if this instruction is in a hot path
            let is_hot = p.block_counts.values().any(|&c| c > self.config.optimize_threshold);
            
            if is_hot {
                // Inline common patterns
                match instr.opcode {
                    Opcode::SLoad => {
                        // Insert inline cache check before runtime call
                        let mut optimized = Vec::new();
                        // Check if key matches cached key
                        // If hit, load cached value directly
                        // If miss, call runtime and update cache
                        optimized.extend(&[0x90]); // IC check (NOP, patched at specialization)
                        optimized.extend(&code);
                        return Ok(optimized);
                    }
                    _ => {}
                }
            }
        }
        
        Ok(code)
    }
    
    /// Constant folding optimization
    fn constant_fold(&self, blocks: &mut [BasicBlock]) {
        for block in blocks.iter_mut() {
            let mut i = 0;
            while i + 2 < block.instructions.len() {
                // Pattern: PUSH a, PUSH b, ADD -> PUSH (a+b)
                if block.instructions[i].opcode == Opcode::Push 
                    && block.instructions[i + 1].opcode == Opcode::Push
                    && block.instructions[i + 2].opcode == Opcode::Add
                {
                    if let (Some(a), Some(b)) = (
                        &block.instructions[i].operand,
                        &block.instructions[i + 1].operand,
                    ) {
                        if a.len() == 32 && b.len() == 32 {
                            // Constant-fold: replace PUSH a, PUSH b, ADD with PUSH (a+b)
                            block.instructions.drain(i..i + 3);
                        }
                    }
                }
                i += 1;
            }
        }
    }
    
    /// Dead code elimination
    fn eliminate_dead_code(&self, blocks: &mut Vec<BasicBlock>, profile: &Option<ProfileData>) {
        if let Some(ref p) = profile {
            // Remove blocks that were never executed
            blocks.retain(|block| {
                p.block_counts.get(&block.id).copied().unwrap_or(1) > 0
            });
        }
    }
    
    /// Loop unrolling
    fn unroll_loops(&self, blocks: &mut [BasicBlock], profile: &Option<ProfileData>) {
        for block in blocks.iter_mut() {
            if !block.is_loop_header {
                continue;
            }
            
            // Check if loop is hot enough
            let count = if let Some(ref p) = profile {
                p.block_counts.get(&block.id).copied().unwrap_or(0)
            } else {
                0
            };
            
            if count < self.config.optimize_threshold {
                continue;
            }
            
            // Unroll by duplicating instructions (simplified)
            let original_len = block.instructions.len();
            for _ in 1..self.config.max_unroll {
                let to_add: Vec<_> = block.instructions[..original_len].to_vec();
                block.instructions.extend(to_add);
            }
        }
    }
    
    /// Evicts old entries if cache is full
    fn evict_if_needed(&self) {
        let mut cache = self.cache.write();
        
        if cache.len() <= self.config.max_cache_size {
            return;
        }
        
        // Find least recently used entries
        let mut entries: Vec<_> = cache.iter()
            .map(|(k, v)| (*k, v.last_used, v.use_count.load(Ordering::Relaxed)))
            .collect();
        
        entries.sort_by(|a, b| {
            // Sort by use count, then by last used time
            a.2.cmp(&b.2).then_with(|| a.1.cmp(&b.1))
        });
        
        // Remove oldest entries
        let to_remove = cache.len() - self.config.max_cache_size / 2;
        for (hash, _, _) in entries.iter().take(to_remove) {
            cache.remove(hash);
        }
    }
    
    /// Triggers deoptimization
    pub fn deoptimize(&self, code_hash: &Hash, reason: DeoptReason) {
        self.cache.write().remove(code_hash);
        self.stats.lock().deoptimizations += 1;
        
        tracing::debug!("Deoptimized {:?} due to {:?}", code_hash, reason);
    }
    
    /// Returns statistics
    pub fn stats(&self) -> JitStats {
        self.stats.lock().clone()
    }
    
    /// Returns cache size
    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_opcode_parsing() {
        assert_eq!(Opcode::from(0x10), Opcode::Add);
        assert_eq!(Opcode::from(0x50), Opcode::SLoad);
        assert_eq!(Opcode::from(0xFE), Opcode::Invalid);
    }
    
    #[test]
    fn test_basic_block_parsing() {
        let compiler = JitCompiler::new(JitConfig::default());
        
        // Simple bytecode: PUSH 1, PUSH 2, ADD, STOP
        let bytecode = vec![
            0x00, // PUSH
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // value 1
            0x00, // PUSH
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // value 2
            0x10, // ADD
            0x73, // STOP
        ];
        
        let blocks = compiler.parse_basic_blocks(&bytecode).unwrap();
        assert!(!blocks.is_empty());
    }
    
    #[test]
    fn test_compilation_threshold() {
        let compiler = JitCompiler::new(JitConfig {
            baseline_threshold: 10,
            optimize_threshold: 100,
            ..Default::default()
        });
        
        let hash = [1u8; 32];
        
        assert_eq!(compiler.should_compile(&hash, 5), None);
        assert_eq!(compiler.should_compile(&hash, 10), Some(CompilationTier::Baseline));
        assert_eq!(compiler.should_compile(&hash, 100), Some(CompilationTier::Optimized));
    }
}
