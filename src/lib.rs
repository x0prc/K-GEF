pub mod firmware;
pub mod analysis;
pub mod graph;
pub mod semantic;

pub use firmware::{unpack_firmware, index_binaries, BinaryInfo};
pub use analysis::{analyze_all, analyze_binary, AnalysisResult, Function, CallEdge, StringRef, ImportRef};
pub use graph::{build_graph, FwGraph, NodeKind, EdgeKind};
pub use semantic::{tag_functions, apply_tags_to_graph, FunctionTags};