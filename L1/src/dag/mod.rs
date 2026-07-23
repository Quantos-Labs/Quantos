// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

mod graph;
mod ordering;

pub use graph::*;
pub use ordering::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DAGError {
    #[error("Vertex not found: {0}")]
    VertexNotFound(String),
    #[error("Invalid parent reference")]
    InvalidParent,
    #[error("Cycle detected")]
    CycleDetected,
    #[error("Too few parents: minimum {min}, got {got}")]
    TooFewParents { min: usize, got: usize },
    #[error("Too many parents: maximum {max}, got {got}")]
    TooManyParents { max: usize, got: usize },
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Memory exhausted: {0}")]
    MemoryExhausted(String),
    #[error("Height overflow at {0}")]
    HeightOverflow(u64),
    #[error("Traversal limit exceeded: {0}")]
    TraversalLimitExceeded(usize),
    #[error("Invalid vertex: {0}")]
    InvalidVertex(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Shard limit exceeded: {0}")]
    ShardLimitExceeded(usize),
    #[error("Children limit exceeded for vertex")]
    ChildrenLimitExceeded,
}

pub type DAGResult<T> = Result<T, DAGError>;
