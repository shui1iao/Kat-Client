pub mod error;
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

pub mod installer_result;

pub mod user_store;
pub mod preferences;

pub mod lifecycle;

pub mod backups;
pub mod safe_log;

pub mod diagnostics;

pub mod window_geometry;

pub mod document;

pub mod installer_files;

pub mod installer_update;

#[cfg(any(windows, test))]
mod wintun_query;

#[cfg(test)]
mod tun_monitor_tests;

#[cfg(any(windows,test))]
mod tun_ready;

pub mod installed_handoff;

pub mod install_location;

pub mod original_flow;

pub mod service_read_acl;

#[cfg(all(test, not(windows)))]
#[path = "windows/bridge_image_path.rs"]
mod bridge_image_path_tests;

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
