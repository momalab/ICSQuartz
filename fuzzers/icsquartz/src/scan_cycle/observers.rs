use super::*;

use std::borrow::Cow;

use libafl::{executors::ExitKind, inputs::UsesInput, observers::Observer, Error};
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

/// An observer looking at the backtrace after the harness crashes
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanCycleStateObserver {
    observer_name: Cow<'static, str>,

    // Dynamically track the program state
    program_state_pre_exec: Vec<u8>,
    program_state_post_exec: Vec<u8>,
}

impl ScanCycleStateObserver {
    /// Creates a new [`ScanCycleObserver`] with the given name.
    #[must_use]
    pub fn new<S>(observer_name: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self {
            observer_name: observer_name.into(),
            program_state_pre_exec: vec![0; unsafe { program_state_size as usize }],
            program_state_post_exec: vec![0; unsafe { program_state_size as usize }],
        }
    }

    /// Check whether the pre-execution state is equal to the post-execution state
    pub fn state_changed(&self) -> bool {
        self.program_state_pre_exec != self.program_state_post_exec
    }
}

impl<S> Observer<S> for ScanCycleStateObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) -> Result<(), Error> {
        // Copy the program state into the observer
        unsafe {
            std::ptr::copy(
                program_state_start,
                self.program_state_pre_exec.as_mut_ptr(),
                program_state_size as usize,
            );
        }

        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // Copy the program state into the observer
        unsafe {
            std::ptr::copy(
                program_state_start,
                self.program_state_post_exec.as_mut_ptr(),
                program_state_size as usize,
            );

            // Update our global state tracker (awful)
            // TODO - refactor to use an observer handle and the feedback can grab it
            STATE_CHANGED = self.state_changed();
        }

        Ok(())
    }
}

impl Named for ScanCycleStateObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.observer_name
    }
}
