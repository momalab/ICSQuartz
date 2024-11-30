use std::{borrow::Cow, time::Duration};

use libafl::{
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    observers::ObserversTuple,
    state::{HasStartTime, State},
    Error, HasMetadata, SerdeAny,
};
use libafl_bolts::{current_time, Named};
use serde::{Deserialize, Serialize};

#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct CrashTimeMetadata {
    pub time_to_find: Duration,
}

/// Records the number of scan cycles for a given testcase.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrashTimeFeedback {}

impl<S> Feedback<S> for CrashTimeFeedback
where
    S: State + HasMetadata + HasStartTime,
{
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
        Ok(false)
    }

    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error> {
        let now = current_time();
        let start = state.start_time();
        testcase.add_metadata(CrashTimeMetadata {
            time_to_find: now - *start,
        });
        Ok(())
    }
}

impl Named for CrashTimeFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CrashTimeFeedback");
        &NAME
    }
}

impl CrashTimeFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}
