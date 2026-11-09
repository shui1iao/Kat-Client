pub mod identity;
pub mod proxy;
pub mod watchdog;
pub mod network;
pub mod netapi;
pub mod security;
pub mod pipe;
pub mod job;
#[path="legacy_tun_recovery.rs"]pub mod engine;
pub mod scm;
pub mod firewall;
pub mod installer;
pub mod service;
pub mod service_client;

pub mod installer_result;

pub mod autostart;

pub mod dialogs;

#[cfg(feature="desktop")]pub mod window_state;

#[cfg(feature="desktop")]pub mod installed_handoff;
#[cfg(feature="desktop")]pub mod shortcuts;

pub mod install_location;
pub mod installed_app;
#[cfg(feature="desktop")]pub mod setup_bridge;

// c50 has no legacy bridge registration/session endpoints.

mod service_acl;

mod self_read;

pub mod update_handoff;
pub mod update_install;
#[cfg(feature="desktop")]pub mod update_bridge;

pub mod elevated;
pub(crate) mod elevated_stderr;
pub mod core_tun_recovery;
