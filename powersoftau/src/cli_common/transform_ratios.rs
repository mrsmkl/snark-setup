use crate::parameters::ContributionMode;
use crate::{batched_accumulator::BatchedAccumulator, parameters::CeremonyParams};
use memmap::*;
use snark_utils::{calculate_hash, print_hash, CheckForCorrectness, UseCompression};
use std::fs::OpenOptions;
use zexe_algebra::PairingEngine as Engine;

pub fn transform_ratios<T: Engine + Sync>(response_filename: &str, parameters: &CeremonyParams<T>) {
    println!(
        "Will verify and decompress a contribution to accumulator for 2^{} powers of tau",
        parameters.size
    );

    // Try to load response file from disk.
    let response_reader = OpenOptions::new()
        .read(true)
        .open(response_filename)
        .expect("unable open response file in this directory");

    {
        let parameters = CeremonyParams::<T>::new(
            parameters.contribution_mode,
            0,
            parameters.powers_g1_length,
            parameters.size,
            parameters.batch_size,
        );
        let metadata = response_reader
            .metadata()
            .expect("unable to get filesystem metadata for response file");
        let expected_response_length = match parameters.contribution_mode {
            ContributionMode::Chunked => parameters.accumulator_size - parameters.hash_size,
            ContributionMode::Full => parameters.accumulator_size,
        };
        if metadata.len() != (expected_response_length as u64) {
            panic!(
                "The size of response file should be {}, but it's {}, so something isn't right.",
                expected_response_length,
                metadata.len()
            );
        }
    }

    let response_readable_map = unsafe {
        MmapOptions::new()
            .map(&response_reader)
            .expect("unable to create a memory map for input")
    };

    let response_hash = calculate_hash(&response_readable_map);

    println!("Hash of the response file for verification:");
    print_hash(&response_hash);

    // check that it follows the protocol
    println!(
        "Verifying a contribution to contain proper powers and correspond to the public key..."
    );

    let res = BatchedAccumulator::verify_transformation_ratios(
        &response_readable_map,
        UseCompression::No,
        CheckForCorrectness::No,
        &parameters,
    );

    if let Err(e) = res {
        println!("Verification failed: {}", e);
        panic!("INVALID CONTRIBUTION!!!");
    } else {
        println!("Verification succeeded!");
    }
}
