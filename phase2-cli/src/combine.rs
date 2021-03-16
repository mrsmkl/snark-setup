use phase2::parameters::MPCParameters;
use setup_utils::{print_hash, CheckForCorrectness, SubgroupCheckMode, UseCompression};

use algebra::{CanonicalSerialize, BW6_761};

use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::info;

const INITIAL_IS_COMPRESSED: UseCompression = UseCompression::No;
const CONTRIBUTION_IS_COMPRESSED: UseCompression = UseCompression::No;
const COMBINED_IS_COMPRESSED: UseCompression = UseCompression::No;

pub fn combine(
    initial_query_filename: &str,
    initial_full_filename: &str,
    response_list_filename: &str,
    combined_filename: &str,
) {
    info!("Combining phase 2 {} {}", combined_filename, response_list_filename);

    let response_list_reader =
        BufReader::new(File::open(response_list_filename).expect("should have opened the response list"));

    let full_contents = std::fs::read(initial_full_filename).expect("should have initial full parameters");
    let full_parameters = MPCParameters::<BW6_761>::read_fast(
        full_contents.as_slice(),
        INITIAL_IS_COMPRESSED,
        CheckForCorrectness::No,
        false,
        SubgroupCheckMode::Auto,
    )
    .expect("should have read full parameters");

    let mut query_contents =
        std::io::Cursor::new(std::fs::read(initial_query_filename).expect("should have read initial query"));
    let query_parameters = MPCParameters::<BW6_761>::read_groth16_fast(
        &mut query_contents,
        INITIAL_IS_COMPRESSED,
        CheckForCorrectness::No,
        false,
        SubgroupCheckMode::Auto,
    )
    .expect("should have deserialized initial query params");

    let mut all_parameters = vec![];
    for line in response_list_reader.lines() {
        let line = line.expect("should have read line");
        let contents = std::fs::read(line).expect("should have read response");
        let parameters = MPCParameters::<BW6_761>::read_fast(
            contents.as_slice(),
            CONTRIBUTION_IS_COMPRESSED,
            CheckForCorrectness::No,
            false,
            SubgroupCheckMode::Auto,
        )
        .expect("should have read parameters");
        all_parameters.push(parameters);
    }

    let combined =
        MPCParameters::<BW6_761>::combine(&query_parameters, &all_parameters).expect("should have combined parameters");

    let contributions_hash = full_parameters
        .verify(&combined)
        .expect("should have verified successfully");
    info!("Contributions hashes:");
    for contribution_hash in contributions_hash {
        print_hash(&contribution_hash[..]);
    }

    let mut combined_contents = vec![];
    combined
        .write(&mut combined_contents, COMBINED_IS_COMPRESSED)
        .expect("should have written combined");
    std::fs::write(combined_filename, &combined_contents).expect("should have written combined file");

    let mut combined_parameters_contents = vec![];
    combined
        .params
        .serialize_uncompressed(&mut combined_parameters_contents)
        .expect("should have serialized combined parameters");
    std::fs::write(format!("{}.params", combined_filename), &combined_parameters_contents)
        .expect("should have written combined parameters file");
}
