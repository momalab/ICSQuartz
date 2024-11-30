use super::*;

use std::borrow::Cow;

use libafl::{
    inputs::HasMutatorBytes,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, Named};

// This is our structure that will implement Mutator
// add any needed members here
pub struct ScanCycleInputMutator {
    name: Cow<'static, str>,
    disabled: bool,

    // Inputs
    program_input_size: usize,
    program_input_fresh: Vec<u8>,
}

impl ScanCycleInputMutator {
    pub fn new(program_input_size: usize, program_input_fresh: Vec<u8>, disabled: bool) -> Self {
        Self {
            name: Cow::from("ScanCycleMutator"),
            disabled,
            program_input_size,
            program_input_fresh,
        }
    }
}

impl<I, S> Mutator<I, S> for ScanCycleInputMutator
where
    I: HasMutatorBytes,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        // If the state has changed, current fuzzer mutations are working
        // and no need to inject something.
        // if unsafe { STATE_CHANGED } {
        //     return Ok(MutationResult::Skipped);
        // }
        if self.disabled {
            return Ok(MutationResult::Skipped);
        }

        // Resize the input to the expected size
        input.resize(self.program_input_size, 0);

        // choose a random byte
        let byte_idx = state.rand_mut().below(self.program_input_size);

        // copy program_state_fresh[idx] to input[idx]
        unsafe {
            input.bytes_mut()[byte_idx] = *program_state_fresh.offset(byte_idx as isize);
        }

        // println!(
        //     "Interrupted mutation with ScanCycleMutator at byte {} = ({})",
        //     byte_idx,
        //     input.bytes_mut()[byte_idx] as u64,
        // );

        Ok(MutationResult::Mutated)
    }
}

impl Named for ScanCycleInputMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
