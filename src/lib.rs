//! enclos: create sandboxes, install agent runtimes in them and run agents
//! there, with policy and an audit log. The `enclos` binary is a thin CLI
//! over this library; every client calls the [`engine::Engine`].

pub mod audit;
pub mod backend;
pub mod config;
pub mod engine;
pub mod error;
#[cfg(test)]
mod host_ports;
pub mod layout;
pub mod lifecycle;
pub mod model;
pub mod net;
pub mod notes;
pub mod policy;
pub mod probes;
pub mod proxy;
pub mod runtime;
pub mod secrets;
pub mod service;
pub mod state;
