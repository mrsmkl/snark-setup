use gumdrop::Options;
use powersoftau::cli_common::{
    contribute, new_challenge, transform, transform_full, Command, CurveKind, PowersOfTauOpts,
};
use powersoftau::parameters::CeremonyParams;
use snark_utils::{beacon_randomness, derive_rng_from_seed};

use std::process;
use std::time::Instant;
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};
use zexe_algebra::{Bls12_377, Bls12_381, PairingEngine as Engine, BW6_761};

#[macro_use]
extern crate hex_literal;

fn main() {
    Subscriber::builder()
        .with_target(false)
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts: PowersOfTauOpts = PowersOfTauOpts::parse_args_default_or_exit();

    match opts.curve_kind {
        CurveKind::Bls12_381 => execute_cmd::<Bls12_381>(opts),
        CurveKind::Bls12_377 => execute_cmd::<Bls12_377>(opts),
        CurveKind::BW6 => execute_cmd::<BW6_761>(opts),
    };
}

fn execute_cmd<E: Engine>(opts: PowersOfTauOpts) {
    let parameters = CeremonyParams::<E>::new(opts.power, opts.batch_size, opts.chunk_index);

    let command = opts.clone().command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", PowersOfTauOpts::usage());
        process::exit(2)
    });

    let now = Instant::now();
    match command {
        Command::New(opt) => {
            new_challenge(&opt.challenge_fname, &parameters);
        }
        Command::Contribute(opt) => {
            // contribute to the randomness
            let seed = hex::decode(&opts.seed).expect("seed should be a hex string");
            let rng = derive_rng_from_seed(&seed);
            contribute(&opt.challenge_fname, &opt.response_fname, &parameters, rng);
        }
        Command::Beacon(opt) => {
            // use the beacon's randomness
            // Place block hash here (block number #564321)
            let beacon_hash: [u8; 32] =
                hex!("0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620");
            let rng = derive_rng_from_seed(&beacon_randomness(beacon_hash));
            contribute(&opt.challenge_fname, &opt.response_fname, &parameters, rng);
        }
        Command::VerifyAndTransformChunk(opt) => {
            // we receive a previous participation, verify it, and generate a new challenge from it
            transform(
                &opt.challenge_fname,
                &opt.response_fname,
                &opt.new_challenge_fname,
                &parameters,
            );
        }
        Command::VerifyAndTransformFull(opt) => {
            // we receive a previous participation, verify it, and generate a new challenge from it
            transform_full(
                &opt.challenge_fname,
                &opt.response_fname,
                &opt.new_challenge_fname,
                &parameters,
            );
        }
    };

    let new_now = Instant::now();
    println!(
        "Executing {:?} took: {:?}",
        opts,
        new_now.duration_since(now)
    );
}
