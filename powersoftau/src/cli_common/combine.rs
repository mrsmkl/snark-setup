use crate::{batched_accumulator::BatchedAccumulator, parameters::CeremonyParams};
use memmap::*;
use snark_utils::UseCompression;
use std::fs::{File, OpenOptions};
use zexe_algebra::PairingEngine as Engine;

use std::io::{BufRead, BufReader};

const CONTRIBUTION_IS_COMPRESSED: UseCompression = UseCompression::Yes;
const COMPRESS_NEW_COMBINED: UseCompression = UseCompression::No;

pub fn combine<T: Engine + Sync>(
    response_list_filename: &str,
    combined_filename: &str,
    parameters: &CeremonyParams<T>,
) {
    println!("Will combine contributions",);

    let mut readers = vec![];

    let response_list_reader = BufReader::new(
        File::open(response_list_filename).expect("should have opened the response list"),
    );
    for (chunk_index, line) in response_list_reader.lines().enumerate() {
        let line = line.expect("should have read line");
        let parameters = parameters.specialize_to_chunk(chunk_index);
        let response_reader = OpenOptions::new()
            .read(true)
            .open(line)
            .expect("unable open response file in this directory");
        {
            let metadata = response_reader
                .metadata()
                .expect("unable to get filesystem metadata for response file");
            let expected_response_length = match CONTRIBUTION_IS_COMPRESSED {
                UseCompression::Yes => parameters.contribution_size,
                UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
            };
            if metadata.len() != (expected_response_length as u64) {
                panic!(
                    "The size of response file should be {}, but it's {}, so something isn't right.",
                    expected_response_length,
                    metadata.len()
                );
            }
        }

        unsafe {
            readers.push(
                MmapOptions::new()
                    .map(&response_reader)
                    .expect("should have mapped the reader"),
            );
        }
    }

    let parameters_for_output =
        CeremonyParams::<T>::new(0, parameters.size, parameters.powers_g1_length);
    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(combined_filename)
        .expect("unable to create new combined file in this directory");

    writer
        .set_len(
            parameters_for_output.accumulator_size as u64 - parameters_for_output.hash_size as u64,
        )
        .expect("must make output file large enough");

    let mut writable_map = unsafe {
        MmapOptions::new()
            .map_mut(&writer)
            .expect("unable to create a memory map for output")
    };

    let parameters = CeremonyParams::<T>::new(0, parameters.size, parameters.batch_size);
    let res = BatchedAccumulator::combine(
        readers
            .iter()
            .map(|r| r.as_ref())
            .collect::<Vec<_>>()
            .as_slice(),
        CONTRIBUTION_IS_COMPRESSED,
        &mut writable_map,
        COMPRESS_NEW_COMBINED,
        &parameters,
    );

    if let Err(e) = res {
        println!("Combining failed: {}", e);
        panic!("INVALID CONTRIBUTIONS!!!");
    } else {
        println!("Combining succeeded!");
    }
}
