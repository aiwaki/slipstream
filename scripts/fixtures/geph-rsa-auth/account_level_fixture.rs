// Exact enum excerpt from geph5-broker-protocol 0.4.3; no broker crate execution.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountLevel {
    Free,
    Plus,
}
