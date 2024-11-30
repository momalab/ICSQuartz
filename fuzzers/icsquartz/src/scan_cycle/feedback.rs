use super::*;

use std::{borrow::Cow, cell::UnsafeCell, time::Duration};

use core::marker::PhantomData;

use libafl::{
    corpus::Testcase,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::Feedback,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::ObserversTuple,
    state::{HasExecutions, HasStartTime, State},
    Error, HasMetadata, SerdeAny,
};
use libafl_bolts::{current_time, Named};
use serde::{Deserialize, Serialize};

#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct ScanCycleMetadata {
    pub scan_cycles: usize,
    // pub time_to_find: Duration,
}

/// Records the number of scan cycles for a given testcase.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanCycleCountFeedback {}

impl<S> Feedback<S> for ScanCycleCountFeedback
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
        // let now = current_time();
        // let start = state.start_time();
        testcase.add_metadata(ScanCycleMetadata {
            scan_cycles: unsafe { scan_cycle },
            // time_to_find: now - *start,
        });
        Ok(())
    }
}

impl Named for ScanCycleCountFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("ScanCycleCountFeedback");
        &NAME
    }
}

impl ScanCycleCountFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

/// Allow scan cycle reset data to be stored in the state.
#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct ScanCycleResetMetadata {
    pub reset_count: usize,
    pub stale_count: usize,
    pub soft_max: usize,
}

/// Scan Cycle Reset Feedback
/// Resets the current scan cycle when necessary.
/// Always returns not interesting (NOP feedback).
pub struct ScanCycleResetFeedback {}

impl ScanCycleResetFeedback {
    pub fn new() -> Self {
        Self {}
    }
    fn update_execs<S, EM>(
        &self,
        state: &mut S,
        manager: &mut impl EventFirer<State = S>,
    ) -> Result<(), Error>
    where
        S: State + HasExecutions,
        EM: EventFirer<State = S>,
    {
        manager.fire(
            state,
            Event::UpdateUserStats {
                name: Cow::from("executions_"),
                value: UserStats::new(
                    UserStatsValue::Number(*state.executions()),
                    AggregatorOps::Sum,
                ),
                phantom: PhantomData,
            },
        )?;

        Ok(())
    }
}

impl<S> Feedback<S> for ScanCycleResetFeedback
where
    S: State + HasMetadata + HasExecutions,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        // Init the state with some initial metadata
        state.add_metadata(ScanCycleResetMetadata {
            reset_count: 0,
            stale_count: 0,
            soft_max: 0,
        });

        Ok(())
    }

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // Allow scan cycle max to increase if state is moving forward
        unsafe {
            if SCAN_CYCLE_SOFT_MAX <= 2 {
                // Ensure that we persist softmax between restarts
                let metadata: &mut &mut ScanCycleResetMetadata =
                    &mut state.metadata_mut::<ScanCycleResetMetadata>().unwrap();

                // Initial case
                if metadata.soft_max <= 2 {
                    metadata.soft_max = 2;
                }
                SCAN_CYCLE_SOFT_MAX = metadata.soft_max;
            }

            // Run safety check
            if STATE_CHANGED == true
                && scan_cycle >= SCAN_CYCLE_SOFT_MAX
                && scan_cycle < SCAN_CYCLE_HARD_MAX
            {
                // Fetch and store count from metadata
                let new_count = {
                    let metadata: &mut &mut ScanCycleResetMetadata =
                        &mut state.metadata_mut::<ScanCycleResetMetadata>().unwrap();
                    metadata.soft_max = scan_cycle + 1;
                    SCAN_CYCLE_SOFT_MAX = scan_cycle + 1;

                    // scan_cycle_max = SCAN_CYCLE_SOFT_MAX;

                    metadata.soft_max
                };

                // Fire a state reset event
                if new_count % 5 == 0 {
                    self.update_execs::<S, EM>(state, manager)?;
                    manager.fire(
                        state,
                        Event::UpdateUserStats {
                            name: Cow::from("soft_scan_cycle_limit_increase_"),
                            value: UserStats::new(
                                UserStatsValue::Number(new_count as u64),
                                AggregatorOps::Sum,
                            ),
                            phantom: PhantomData,
                        },
                    )?;
                }
            }
        }

        // If the state has stayed the same, we'll reset the state to fresh!
        unsafe {
            if STATE_CHANGED == false && ENABLE_STATE_RESETS == true {
                println!("Resetting scan cycle!");
                // Copy fresh state to the start
                std::ptr::copy(program_state_fresh, program_state_start, program_state_size);

                // Reset the state change flag
                STATE_CHANGED = true;

                // Reset scan cycle counter
                scan_cycle = 0;

                // Fetch and store count from metadata
                let new_count = {
                    let metadata = &mut state.metadata_mut::<ScanCycleResetMetadata>().unwrap();
                    metadata.reset_count = metadata.reset_count + 1;
                    metadata.reset_count
                };

                // Fire a state reset event
                if new_count % 1000 == 0 {
                    self.update_execs::<S, EM>(state, manager)?;
                    manager.fire(
                        state,
                        Event::UpdateUserStats {
                            name: Cow::from("stale_state_"),
                            value: UserStats::new(
                                UserStatsValue::Number(new_count as u64),
                                AggregatorOps::Sum,
                            ),
                            phantom: PhantomData,
                        },
                    )?;
                }
            } else if STATE_CHANGED == false && ENABLE_STATE_RESETS == false {
                // Fetch and store count from metadata
                let new_count = {
                    let metadata = &mut state.metadata_mut::<ScanCycleResetMetadata>().unwrap();
                    metadata.stale_count = metadata.stale_count + 1;
                    metadata.stale_count
                };

                if new_count % 1000 == 0 {
                    self.update_execs::<S, EM>(state, manager)?;
                    manager.fire(
                        state,
                        Event::UpdateUserStats {
                            name: Cow::from("stale_state_"),
                            value: UserStats::new(
                                UserStatsValue::Number(new_count as u64),
                                AggregatorOps::Sum,
                            ),
                            phantom: PhantomData,
                        },
                    )?;
                }
            }
        }

        // Update executions (testrun)
        let executions = state.executions();
        if executions % 10000 == 0 {
            self.update_execs::<S, EM>(state, manager)?;
        }

        // Always return false
        Ok(false)
    }
}

impl Named for ScanCycleResetFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("ScanCycleRestFeedback");
        &NAME
    }
}
