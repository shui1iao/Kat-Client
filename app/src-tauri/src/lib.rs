pub mod error;
pub mod transport_diagnostics;
pub mod tun_diagnostics;
pub mod protocol;
pub mod supervisor;
#[cfg(windows)]
pub mod windows;
#[cfg(all(windows, feature = "desktop"))]
pub mod desktop;

pub mod ownership;

pub mod service_protocol;
pub mod transaction;
pub mod apply_policy;

pub mod firewall_rule;
pub mod installer_result;

pub mod user_store;
pub mod preferences;

pub mod lifecycle;

pub mod document_files;
pub mod safe_log;
pub mod log_context;
pub mod safe_archive;
pub mod crash_private;

pub mod diagnostics;

pub mod window_geometry;

pub mod document;

pub mod installer_files;

pub mod installer_update;

#[cfg(any(windows, test))]
mod wintun_query;

#[cfg(test)]
mod tun_monitor_tests;



pub mod installed_handoff;

pub mod install_location;



pub mod service_read_acl;


pub mod service_self_read;

pub mod setup_feedback;

pub mod tray_lifecycle;

#[cfg(test)]
mod command_acl_tests;

pub mod tray_controls;

#[cfg(all(windows,feature="desktop"))]
mod tray_popup;

pub mod core_process;

#[cfg(any(all(windows, feature = "desktop"), test))]
mod acrylic;

pub mod update_key;
pub mod update_manifest;
pub mod update_check;

pub mod elevated_protocol;
pub mod elevation_launch;

pub mod watchdog_control;

#[cfg(windows)]
pub use windows::core_tun_recovery::journal as core_tun_journal;
#[cfg(not(windows))]
#[path = "windows/core_tun_journal.rs"]
pub mod core_tun_journal;
