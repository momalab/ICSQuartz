//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.
use core::time::Duration;
use std::{default, env, net::SocketAddr, path::PathBuf};

use asan_feedback::AsanFeedback;
use clap::{self, Parser};
use crash_time_feedback::CrashTimeFeedback;
use libafl::{
    corpus::{InMemoryCorpus, InMemoryOnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_and_fast, feedback_not, feedback_or,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::{MultiMonitor, OnDiskJSONMonitor},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{BacktraceObserver, CanTrack, HitcountsMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, QueueScheduler,
        StdWeightedScheduler,
    },
    stages::mutational::StdMutationalStage,
    state::StdState,
    Error, Evaluator,
};
use libafl_bolts::{
    core_affinity::Cores,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Handled, Merge},
    AsSlice,
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer};
use mimalloc::MiMalloc;
extern crate libc;

pub mod asan_feedback;
pub mod crash_time_feedback;
#[cfg(feature = "scan_cycle")]
pub mod scan_cycle;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Parse a millis string to a [`Duration`]. Used for arg parsing.
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "libfuzzer_libpng_launcher",
    about = "A libfuzzer-like fuzzer for libpng with llmp-multithreading support and a launcher",
    author = "Andrea Fioraldi <andreafioraldi@gmail.com>, Dominik Maier <domenukk@gmail.com>"
)]
struct Opt {
    #[arg(
        short,
        long,
        value_parser = Cores::from_cmdline,
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        name = "CORES",
        default_value = "2"
    )]
    cores: Cores,

    #[arg(
        short = 'p',
        long,
        help = "Choose the broker TCP port, default is 1337",
        name = "PORT",
        default_value = "1337"
    )]
    broker_port: u16,

    #[arg(short = 'a', long, help = "Specify a remote broker", name = "REMOTE")]
    remote_broker_addr: Option<SocketAddr>,

    #[arg(
        short,
        long,
        help = "Set a corpus directory",
        name = "CORPUS",
        default_value = "./corpus"
    )]
    corpus: PathBuf,

    #[arg(
        short,
        long,
        help = "Set the output directory",
        name = "CRASHES",
        default_value = "./crashes"
    )]
    crashes: PathBuf,

    #[arg(
    value_parser = timeout_from_millis_str,
    short,
    long,
    help = "Set the exeucution timeout in milliseconds",
    name = "TIMEOUT",
    default_value = "10000"
    )]
    timeout: Duration,

    #[arg(
        short,
        long,
        help = "Set the statistic file to log to",
        name = "STATS",
        default_value = "fuzzer_stats.json"
    )]
    fuzzer_stats: PathBuf,

    #[arg(
        short,
        long,
        help = "Set the seed value",
        name = "SEED",
        default_value = "1234"
    )]
    seed: u64,

    #[arg(
        short,
        long,
        help = "Set the mutator power depth",
        name = "MUTATOR_POWER",
        default_value = "4"
    )]
    mutator_pow: usize,

    #[arg(
        short,
        long,
        help = "Perform state resets when state is stale",
        name = "state_resets",
        default_value = "false"
    )]
    state_resets: bool,

    #[arg(
        short,
        long,
        help = "Set the maximum number of scan cycles to run",
        name = "SCAN_CYCLE_MAX",
        default_value = "100"
    )]
    scan_cycle_max: usize,

    #[arg(
        short,
        long,
        help = "Enable dynamic scan cycle limits",
        name = "DYNAMIC_SCAN_CYCLE",
        default_value = "false"
    )]
    dynamic_scan_cycle: bool,

    #[arg(
        short,
        long,
        help = "Fuzzer output log",
        name = "fuzzer_log",
        default_value = "/dev/null"
    )]
    fuzzer_log: PathBuf,

    #[arg(
        short,
        long,
        help = "Set the min input generation",
        name = "min_input_generation",
        default_value = "128"
    )]
    min_input_generation: usize,
}

extern "C" {
    // Default values
    static PLC_PRG_instance: u8;
    static PLC_PRG_instance_size: usize;
    static PLC_PRG_input_size: usize;
}

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
pub extern "C" fn libafl_main() {
    env_logger::init();
    let opt = Opt::parse();

    let broker_port = opt.broker_port;
    let cores = opt.cores;
    let fuzzer_log = opt.fuzzer_log.to_str().unwrap();
    let scan_cycle_mutator = opt.dynamic_scan_cycle;

    #[cfg(feature = "scan_cycle")]
    unsafe {
        scan_cycle::ENABLE_STATE_RESETS = opt.state_resets;
        scan_cycle::SCAN_CYCLE_HARD_MAX = opt.scan_cycle_max;

        if opt.dynamic_scan_cycle {
            scan_cycle::SCAN_CYCLE_SOFT_MAX = 2;
        } else {
            scan_cycle::SCAN_CYCLE_SOFT_MAX = opt.scan_cycle_max;
        }
        scan_cycle::scan_cycle_max = opt.scan_cycle_max;
    }

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // Print state setup
    let mut program_input_size = unsafe { PLC_PRG_input_size };
    // We need to have a minimum input even if they're not all used to help with generation
    let min_program_input_generated = if program_input_size < opt.min_input_generation {
        opt.min_input_generation
    } else {
        program_input_size * 3 / 2
    };

    let program_input_fresh = unsafe { &PLC_PRG_instance };
    println!("Program input size: {}", program_input_size);
    println!("Program instance size: {}", unsafe {
        PLC_PRG_instance_size
    });
    assert!(program_input_size > 0);
    assert!(program_input_size <= unsafe { PLC_PRG_instance_size });

    #[cfg(feature = "scan_cycle")]
    {
        println!("Program state size: {}", unsafe {
            scan_cycle::program_state_size
        });
        assert!(
            program_input_size + unsafe { scan_cycle::program_state_size }
                == unsafe { PLC_PRG_instance_size }
        );
        // program_input_size = program_input_size - unsafe { program_state_size };
    }

    // Print the default input
    let default_input_bytes =
        unsafe { std::slice::from_raw_parts(program_input_fresh, program_input_size as usize) };
    let initial_input = BytesInput::new(default_input_bytes.to_vec());
    println!("Initial input vector: {:?}", initial_input);

    // Create a shared memory provider
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // Monitoring and logging
    let monitor = MultiMonitor::new(|s| println!("{s}"));
    let monitor = OnDiskJSONMonitor::new(&opt.fuzzer_stats, monitor, |_| true);

    let mut run_client = |state: Option<_>, mut mgr, _core_id| {
        println!("Starting client on core");

        // Create a time observer
        #[cfg(feature = "exec_time")]
        let time_observer = TimeObserver::new("time");

        // Create an observation channel using the coverage map
        let edges_observer =
            HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();

        // Create a stacktrace observer
        let bt_observer = BacktraceObserver::owned(
            "BacktraceObserver",
            libafl::observers::HarnessType::InProcess,
        );

        // Analyze program state across executions
        #[cfg(feature = "scan_cycle")]
        let scan_cycle_observer = scan_cycle::ScanCycleStateObserver::new("scan_cycle");

        // Track coverage
        let mut feedback = MaxMapFeedback::new(&edges_observer);

        // Add crash time metadata to each report
        let mut feedback = feedback_or!(feedback, CrashTimeFeedback::new());

        // Annotate scan cycles on corpus
        #[cfg(feature = "scan_cycle")]
        let mut feedback = feedback_or!(
            feedback,
            scan_cycle::ScanCycleCountFeedback::new(),
            scan_cycle::ScanCycleResetFeedback::new()
        );

        // Annotate execution time on corpus
        #[cfg(feature = "exec_time")]
        let mut feedback = feedback_or!(feedback, TimeFeedback::new(&time_observer));

        #[cfg(not(feature = "asan_crash_feedback"))]
        let mut crash_feedback = CrashFeedback::new();
        #[cfg(feature = "asan_crash_feedback")]
        let mut crash_feedback = AsanFeedback::new();

        // A feedback to choose if an input is a solution or not
        // We want to do the same crash deduplication that AFL does
        let mut objective = feedback_and_fast!(
            // Must be a crash
            crash_feedback,
            // StdErrFeedback::new(stdout_observer.handle(), stderr_observer.handle()),
            // Must have a new backtrace
            // NewHashFeedback::new(&bt_observer),
            // Take it only if trigger new coverage over crashes
            // Uses `with_name` to create a different history from the `MaxMapFeedback` in `feedback` above
            MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer),
            // Annotate crashes with time to find
            feedback_not!(CrashTimeFeedback::new())
        );

        // Annotate scan cycles on solutions
        #[cfg(feature = "scan_cycle")]
        let mut objective = feedback_and_fast!(
            objective,
            feedback_not!(scan_cycle::ScanCycleCountFeedback::new())
        );

        // Annotate execution time on solutions
        #[cfg(feature = "exec_time")]
        let mut objective =
            feedback_and_fast!(objective, feedback_not!(TimeFeedback::new(&time_observer)));

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(opt.seed),
                // Corpus that will be evolved, we keep it in memory and write to disk for performance
                // InMemoryCorpus::new(),
                InMemoryOnDiskCorpus::new(&opt.corpus).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                // InMemoryCorpus::new(),
                InMemoryOnDiskCorpus::new(&opt.crashes).unwrap(),
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Target objectives.
                &mut objective,
            )
            .unwrap()
        });

        println!("We're a client, let's fuzz :)");

        // Base mutations
        let mutations = havoc_mutations();

        // Add scan cycle mutations
        #[cfg(feature = "scan_cycle_mutations")]
        let mutations = mutations.merge(tuple_list!(scan_cycle::ScanCycleInputMutator::new(
            program_input_size,
            default_input_bytes.to_vec(),
            scan_cycle_mutator,
        ),));

        // Create a std mutator
        let mutator = StdScheduledMutator::with_max_stack_pow(mutations, opt.mutator_pow);

        // Build stages
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // Choose a scheduler
        let scheduler = QueueScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            // Execute with the adjusted buffer
            libfuzzer_test_one_input(input.target_bytes().as_slice());

            ExitKind::Ok
        };

        let observers = tuple_list!(edges_observer, bt_observer,);

        #[cfg(feature = "scan_cycle")]
        let observers = observers.merge(tuple_list!(scan_cycle_observer,));

        #[cfg(feature = "exec_time")]
        let observers = observers.merge(tuple_list!(time_observer,));

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = InProcessExecutor::batched_timeout(
            &mut harness,
            observers,
            &mut fuzzer,
            &mut state,
            &mut mgr,
            opt.timeout,
        )?;

        // Call LLVMFUzzerInitialize() if present.
        let args: Vec<String> = env::args().collect();
        if libfuzzer_initialize(&args) == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1");
        }

        // Load the initial PLC_PRG values as the first corpus, and some additional inputs
        if state.must_load_initial_inputs() {
            println!("Loading initial corpus");

            // Create the vector to store all inputs
            let mut generator = vec![];

            generator.push(initial_input.clone()); // Initial values
            generator.push(BytesInput::new(vec![])); // Empty input
            generator.push(BytesInput::new(vec![0; 1])); // One-byte input
            generator.push(BytesInput::new(vec![0; min_program_input_generated])); // Zero values
            generator.push(BytesInput::new(vec![255; min_program_input_generated])); // Max values
            generator.push(BytesInput::new(vec![0; min_program_input_generated / 2])); // Half-size input
            generator.push(BytesInput::new(
                vec![0xAA, 0x55].repeat(min_program_input_generated / 2),
            )); // Alternating pattern
            generator.push(BytesInput::new(vec![0xAB; min_program_input_generated])); // Repeated single byte

            let incrementing_input: Vec<u8> = (0..min_program_input_generated as u8).collect();
            generator.push(BytesInput::new(incrementing_input)); // Incrementing sequence
            let decrementing_input: Vec<u8> =
                (0..min_program_input_generated as u8).rev().collect();
            generator.push(BytesInput::new(decrementing_input)); // Decrementing sequence

            let generator_len = generator.len();

            println!("Running {} initial inputs", generator_len);

            // Pass values into the state
            state
                .generate_initial_inputs_forced(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator.into_iter(),
                    &mut mgr,
                    generator_len,
                )
                .unwrap();

            println!("Loaded {} initial inputs", generator_len);
        }

        // Start fuzzing
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(opt.remote_broker_addr)
        .stdout_file(Some(fuzzer_log))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
