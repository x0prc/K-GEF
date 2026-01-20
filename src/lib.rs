pub mod firmware;
pub mod analysis;
pub mod graph;

pub use firmware::{unpack_firmware, index_binaries, BinaryInfo};
pub use analysis::{analyze_all, analyze_binary, AnalysisResult, Function, CallEdge, StringRef, ImportRef};
pub use graph::{build_graph, FwGraph, NodeKind, EdgeKind};