//! enclos: run AI agents in sandboxes you control, with policy and an audit
//! log. The `enclos` binary is a thin CLI over this library; every client
//! calls the [`engine::Engine`].

pub mod audit;
pub mod backend;
pub mod config;
pub mod engine;
pub mod error;
pub mod layout;
pub mod lifecycle;
pub mod model;
pub mod net;
pub mod policy;
pub mod proxy;
pub mod state;
