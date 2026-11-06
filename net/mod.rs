//! Network rules shared by the policy and the egress proxy (ADRs 0007, 0017),
//! and the budget the proxy and the relay hold their connections to.

pub mod addr;
pub(crate) mod budget;
pub mod host;
