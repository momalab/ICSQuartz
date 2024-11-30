#[cfg(feature = "scan_cycle")]
pub mod feedback;
use std::sync::atomic::AtomicUsize;

#[cfg(feature = "scan_cycle")]
pub use feedback::{ScanCycleCountFeedback, ScanCycleMetadata, ScanCycleResetFeedback};
#[cfg(feature = "scan_cycle")]
pub mod mutators;
#[cfg(feature = "scan_cycle")]
pub use mutators::ScanCycleInputMutator;
#[cfg(feature = "scan_cycle")]
pub mod observers;
#[cfg(feature = "scan_cycle")]
pub use observers::ScanCycleStateObserver;

extern crate libc;

// TOOD - test these with multiple cores (and maybe use atomics)
// Track program state changes
pub static mut STATE_CHANGED: bool = false;

pub static mut ENABLE_STATE_RESETS: bool = false;

pub static mut SCAN_CYCLE_SOFT_MAX: usize = 0;
pub static mut SCAN_CYCLE_HARD_MAX: usize = 0;

#[cfg(feature = "scan_cycle")]
extern "C" {
    // Program state
    pub static program_state_fresh: *mut u8;
    pub static program_state_start: *mut u8;
    pub static program_state_end: *mut u8;
    pub static program_state_size: usize;

    // Scan cycles
    pub static mut scan_cycle: usize;
    pub static mut scan_cycle_max: usize;
}
