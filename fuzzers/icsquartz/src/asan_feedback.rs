use std::borrow::Cow;

use libafl::{
    events::EventFirer, executors::ExitKind, feedbacks::Feedback, observers::ObserversTuple,
    state::State, Error,
};
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};
use std::fs;
use std::process;
use std::time::SystemTime;

extern crate libc;

pub static ASAN_LOG_PATH: &str = "./asanlog"; // TODO make it unique

/// A [`AsanFeedback`] reports as interesting if the target updates the ASAN log file.
/// An update implies a new crash was reported!
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsanFeedback {
    pid: u32,
    last_modified: Option<SystemTime>,
}

impl<S> Feedback<S> for AsanFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let path = format!("{}.{}", ASAN_LOG_PATH, self.pid);

        match fs::metadata(&path) {
            Ok(metadata) => {
                // Modify time of asan file
                let modified_time = metadata.modified().unwrap();

                // Check if we have existing timestamp
                if let Some(last_modified) = self.last_modified {
                    // Older timestamp
                    if modified_time <= last_modified {
                        return Ok(false);
                    }
                }

                // Update timestamp, return true
                self.last_modified = Some(modified_time);
                return Ok(true);
            }
            Err(_) => {
                return Ok(false);
            }
        }
    }
}

impl Named for AsanFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("AsanFeedback");
        &NAME
    }
}

impl AsanFeedback {
    /// Creates a new [`CrashFeedback`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            pid: process::id(),
            last_modified: None,
        }
    }
}
