//! Accumulator which operates on batches of data

use crate::{
    keypair::{PrivateKey, PublicKey},
    parameters::CeremonyParams,
};
use snark_utils::*;
use snark_utils::{BatchDeserializer, BatchSerializer, Deserializer};
use zexe_algebra::{AffineCurve, FpParameters, PairingEngine, PrimeField, ProjectiveCurve, Zero};

use tracing::{debug, info, info_span, trace};

/// Mutable buffer, compression
type Output<'a> = (&'a mut [u8], UseCompression);
/// Buffer, compression
type Input<'a> = (&'a [u8], UseCompression, CheckForCorrectness);

/// Mutable slices with format [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
type SplitBufMut<'a> = (
    &'a mut [u8],
    &'a mut [u8],
    &'a mut [u8],
    &'a mut [u8],
    &'a mut [u8],
);

/// Immutable slices with format [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
type SplitBuf<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8]);

#[allow(type_alias_bounds)]
type AccumulatorElements<E: PairingEngine> = (
    Vec<E::G1Affine>,
    Vec<E::G2Affine>,
    Vec<E::G1Affine>,
    Vec<E::G1Affine>,
    E::G2Affine,
);

#[allow(type_alias_bounds)]
#[allow(unused)]
type AccumulatorElementsRef<'a, E: PairingEngine> = (
    &'a [E::G1Affine],
    &'a [E::G2Affine],
    &'a [E::G1Affine],
    &'a [E::G1Affine],
    &'a E::G2Affine,
);

use crate::parameters::ContributionMode;
/// Helper function to iterate over the accumulator in chunks.
/// `action` will perform an action on the chunk
use itertools::{Itertools, MinMaxResult};

fn iter_chunk(
    parameters: &CeremonyParams<impl PairingEngine>,
    mut action: impl FnMut(usize, usize) -> Result<()>,
) -> Result<()> {
    let (min, max) = match parameters.contribution_mode {
        ContributionMode::Chunked => (
            parameters.chunk_index * parameters.chunk_size,
            std::cmp::min(
                (parameters.chunk_index + 1) * parameters.chunk_size,
                parameters.powers_g1_length,
            ),
        ),
        ContributionMode::Full => (0, parameters.powers_g1_length),
    };
    (min..max)
        .chunks(parameters.batch_size - 1)
        .into_iter()
        .map(|chunk| {
            let (start, end) = match chunk.minmax() {
                MinMaxResult::MinMax(start, end) => {
                    (start, if end >= max - 1 { end + 1 } else { end + 2 })
                } // ensure there's overlap between chunks
                MinMaxResult::OneElement(start) => (
                    start,
                    if start >= max - 1 {
                        start + 1
                    } else {
                        start + 2
                    },
                ),
                _ => return Err(Error::InvalidChunk),
            };
            action(start, end)
        })
        .collect::<Result<_>>()
}

/// Populates the output buffer with an empty accumulator as dictated by Parameters and compression
pub fn init<'a, E: PairingEngine>(
    output: &'a mut [u8],
    parameters: &'a CeremonyParams<E>,
    compressed: UseCompression,
) {
    let span = info_span!("initialize");
    let _enter = span.enter();
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split_mut(output, parameters, compressed);
    let g1_one = &E::G1Affine::prime_subgroup_generator();
    let g2_one = &E::G2Affine::prime_subgroup_generator();
    rayon::scope(|s| {
        s.spawn(|_| {
            tau_g1
                .init_element(g1_one, compressed)
                .expect("could not initialize TauG1 elements")
        });
        s.spawn(|_| {
            tau_g2
                .init_element(g2_one, compressed)
                .expect("could not initialize TauG2 elements")
        });
        s.spawn(|_| {
            alpha_g1
                .init_element(g1_one, compressed)
                .expect("could not initialize Alpha G1 elements")
        });
        s.spawn(|_| {
            beta_g1
                .init_element(g1_one, compressed)
                .expect("could not initialize Beta G1 elements")
        });
        s.spawn(|_| {
            beta_g2
                .init_element(g2_one, compressed)
                .expect("could not initialize the Beta G2 elements")
        });
    });
    info!("accumulator has been initialized");
}

/// Given a public key and the accumulator's digest, it hashes each G1 element
/// along with the digest, and then hashes it to G2.
fn compute_g2_s_key<E: PairingEngine>(
    key: &PublicKey<E>,
    digest: &[u8],
) -> Result<[E::G2Affine; 3]> {
    Ok([
        compute_g2_s::<E>(&digest, &key.tau_g1.0, &key.tau_g1.1, 0)?,
        compute_g2_s::<E>(&digest, &key.alpha_g1.0, &key.alpha_g1.1, 1)?,
        compute_g2_s::<E>(&digest, &key.beta_g1.0, &key.beta_g1.1, 2)?,
    ])
}

/// Reads a list of G1 elements from the buffer to the provided `elements` slice
/// and then checks that their powers pairs ratio matches the one from the
/// provided `check` pair
fn check_power_ratios<E: PairingEngine>(
    (buffer, compression, check_input_for_correctness): (
        &[u8],
        UseCompression,
        CheckForCorrectness,
    ),
    (start, end): (usize, usize),
    elements: &mut [E::G1Affine],
    check: &(E::G2Affine, E::G2Affine),
) -> Result<()> {
    let size = buffer_size::<E::G1Affine>(compression);
    buffer[start * size..end * size].read_batch_preallocated(
        &mut elements[0..end - start],
        compression,
        check_input_for_correctness,
    )?;
    check_same_ratio::<E>(&power_pairs(&elements[..end - start]), check, "Power pairs")?;
    Ok(())
}

/// Reads a list of G1 elements from the buffer to the provided `elements` slice
/// and then checks that their powers pairs ratio matches the one from the
/// provided `check` pair
fn check_elements_are_non_zero_and_in_prime_order_subgroup<C: AffineCurve>(
    (buffer, compression): (&[u8], UseCompression),
    (start, end): (usize, usize),
    elements: &mut [C],
) -> Result<()> {
    let size = buffer_size::<C>(compression);
    buffer[start * size..end * size].read_batch_preallocated(
        &mut elements[0..end - start],
        compression,
        CheckForCorrectness::Both,
    )?;
    // TODO(kobi): replace with batch subgroup check
    let all_in_prime_order_subgroup = elements.iter().all(|p| {
        p.mul(<<C::ScalarField as PrimeField>::Params as FpParameters>::MODULUS)
            .is_zero()
    });
    if !all_in_prime_order_subgroup {
        return Err(Error::IncorrectSubgroup);
    }
    Ok(())
}

/// Reads a list of G2 elements from the buffer to the provided `elements` slice
/// and then checks that their powers pairs ratio matches the one from the
/// provided `check` pair
fn check_power_ratios_g2<E: PairingEngine>(
    (buffer, compression, check_input_for_correctness): (
        &[u8],
        UseCompression,
        CheckForCorrectness,
    ),
    (start, end): (usize, usize),
    elements: &mut [E::G2Affine],
    check: &(E::G1Affine, E::G1Affine),
) -> Result<()> {
    let size = buffer_size::<E::G2Affine>(compression);
    buffer[start * size..end * size].read_batch_preallocated(
        &mut elements[0..end - start],
        compression,
        check_input_for_correctness,
    )?;
    check_same_ratio::<E>(check, &power_pairs(&elements[..end - start]), "Power pairs")?;
    Ok(())
}

/// Reads a chunk of 2 elements from the buffer
fn read_initial_elements<C: AffineCurve>(
    buf: &[u8],
    compressed: UseCompression,
    check_input_for_correctness: CheckForCorrectness,
) -> Result<Vec<C>> {
    read_initial_elements_with_amount(buf, 2, compressed, check_input_for_correctness)
}

/// Reads a chunk of "amount" elements from the buffer
fn read_initial_elements_with_amount<C: AffineCurve>(
    buf: &[u8],
    amount: usize,
    compressed: UseCompression,
    check_input_for_correctness: CheckForCorrectness,
) -> Result<Vec<C>> {
    let batch = amount;
    let size = buffer_size::<C>(compressed);
    let ret = buf[0..batch * size].read_batch(compressed, check_input_for_correctness)?;
    if ret.len() != batch {
        return Err(Error::InvalidLength {
            expected: batch,
            got: ret.len(),
        });
    }
    Ok(ret)
}

/// Verifies that the accumulator was transformed correctly
/// given the `PublicKey` and the so-far hash of the accumulator.
/// This verifies a single chunk and checks only that the points
/// are not zero, that they're in the prime order subgroup.
/// In the first chunk, it also checks the proofs of knowledge
/// and that the elements were correctly multiplied.
pub fn verify_pok_and_correctness<E: PairingEngine>(
    (input, compressed_input, check_input_for_correctness): (
        &[u8],
        UseCompression,
        CheckForCorrectness,
    ),
    (output, compressed_output, check_output_for_correctness): (
        &[u8],
        UseCompression,
        CheckForCorrectness,
    ),
    key: &PublicKey<E>,
    digest: &[u8],
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let span = info_span!("phase1-verify-pok-and-correctness");
    let _enter = span.enter();

    info!("starting...");
    // Split the buffers
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
        split(input, parameters, compressed_input);
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split(output, parameters, compressed_output);

    if parameters.contribution_mode == ContributionMode::Full || parameters.chunk_index == 0 {
        // Ensure the key ratios are correctly produced
        let [tau_g2_s, alpha_g2_s, beta_g2_s] = compute_g2_s_key(&key, &digest)?;
        // put in tuple form for convenience
        // Check the proofs-of-knowledge for tau/alpha/beta
        let tau_single_g1_check = &(key.tau_g1.0, key.tau_g1.1);
        let tau_single_g2_check = &(tau_g2_s, key.tau_g2);
        //let alpha_single_g1_check = &(key.alpha_g1.0, key.alpha_g1.1);
        let alpha_single_g2_check = &(alpha_g2_s, key.alpha_g2);
        let beta_single_g1_check = &(key.beta_g1.0, key.beta_g1.1);
        let beta_single_g2_check = &(beta_g2_s, key.beta_g2);

        let check_ratios = &[
            (
                &(key.tau_g1.0, key.tau_g1.1),
                &(tau_g2_s, key.tau_g2),
                "Tau G1<>G2",
            ),
            (
                &(key.alpha_g1.0, key.alpha_g1.1),
                &(alpha_g2_s, key.alpha_g2),
                "Alpha G1<>G2",
            ),
            (
                &(key.beta_g1.0, key.beta_g1.1),
                &(beta_g2_s, key.beta_g2),
                "Beta G1<>G2",
            ),
        ];

        for (a, b, err) in check_ratios {
            check_same_ratio::<E>(a, b, err)?;
        }
        debug!("key ratios were correctly produced");

        // Ensure that the initial conditions are correctly formed (first 2 elements)
        // We allocate a G1 vector of length 2 and re-use it for our G1 elements.
        // We keep the values of the Tau G1/G2 telements for later use.

        let mut before_g1 = read_initial_elements::<E::G1Affine>(
            in_tau_g1,
            compressed_input,
            check_input_for_correctness,
        )?;
        let mut after_g1 = read_initial_elements::<E::G1Affine>(
            tau_g1,
            compressed_output,
            check_output_for_correctness,
        )?;
        if after_g1[0] != E::G1Affine::prime_subgroup_generator() {
            return Err(VerificationError::InvalidGenerator(ElementType::TauG1).into());
        }
        let before_g2 = read_initial_elements::<E::G2Affine>(
            in_tau_g2,
            compressed_input,
            check_input_for_correctness,
        )?;
        let after_g2 = read_initial_elements::<E::G2Affine>(
            tau_g2,
            compressed_output,
            check_output_for_correctness,
        )?;
        if after_g2[0] != E::G2Affine::prime_subgroup_generator() {
            return Err(VerificationError::InvalidGenerator(ElementType::TauG2).into());
        }
        // Check Tau was multiplied correctly in G1
        check_same_ratio::<E>(
            &(before_g1[1], after_g1[1]),
            tau_single_g2_check,
            "Before-After: Tau G1",
        )?;
        // Check Tau was multiplied correctly in G2
        check_same_ratio::<E>(
            tau_single_g1_check,
            &(before_g2[1], after_g2[1]),
            "Before-After: Tau G2",
        )?;

        // Check Alpha and Beta were multiplied correctly in G1.
        for (before, after, check) in &[
            (in_alpha_g1, alpha_g1, alpha_single_g2_check),
            (in_beta_g1, beta_g1, beta_single_g2_check),
        ] {
            before.read_batch_preallocated(
                &mut before_g1,
                compressed_input,
                check_input_for_correctness,
            )?;
            after.read_batch_preallocated(
                &mut after_g1,
                compressed_output,
                check_output_for_correctness,
            )?;
            check_same_ratio::<E>(
                &(before_g1[0], after_g1[0]),
                check,
                "Before-After: Alpha/Beta[0]",
            )?;
        }

        // Check Beta was multiplied correctly in G1.
        let before_beta_g2 = (&*in_beta_g2)
            .read_element::<E::G2Affine>(compressed_input, check_input_for_correctness)?;
        let after_beta_g2 = (&*beta_g2)
            .read_element::<E::G2Affine>(compressed_output, check_output_for_correctness)?;
        check_same_ratio::<E>(
            beta_single_g1_check,
            &(before_beta_g2, after_beta_g2),
            "Before-After: Beta Single G2[0] G1<>G2",
        )?;
    }

    debug!("initial elements were computed correctly");

    iter_chunk(&parameters, |start, end| {
        // preallocate 2 vectors per batch
        // Ensure that the pairs are created correctly (we do this in chunks!)
        // load `batch_size` chunks on each iteration and perform the transformation
        debug!("verifying chunk from {} to {}", start, end);

        let (start_chunk, end_chunk) = match parameters.contribution_mode {
            ContributionMode::Chunked => (
                start - parameters.chunk_index * parameters.chunk_size,
                end - parameters.chunk_index * parameters.chunk_size,
            ),
            ContributionMode::Full => (start, end),
        };
        let span = info_span!("batch", start, end);
        let _enter = span.enter();
        rayon::scope(|t| {
            let _enter = span.enter();
            t.spawn(|_| {
                let _enter = span.enter();
                let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                check_elements_are_non_zero_and_in_prime_order_subgroup::<E::G1Affine>(
                    (tau_g1, compressed_output),
                    (start_chunk, end_chunk),
                    &mut g1,
                )
                .expect("could not check ratios for Tau G1");

                trace!("tau g1 verification successful");
            });

            if start < parameters.powers_length {
                let end = if start + parameters.batch_size > parameters.powers_length {
                    parameters.powers_length
                } else {
                    end
                };
                let (start_chunk, end_chunk) = match parameters.contribution_mode {
                    ContributionMode::Chunked => (
                        start - parameters.chunk_index * parameters.chunk_size,
                        end - parameters.chunk_index * parameters.chunk_size,
                    ),
                    ContributionMode::Full => (start, end),
                };

                rayon::scope(|t| {
                    let _enter = span.enter();
                    t.spawn(|_| {
                        let _enter = span.enter();
                        let mut g2 = vec![E::G2Affine::zero(); parameters.batch_size];
                        check_elements_are_non_zero_and_in_prime_order_subgroup::<E::G2Affine>(
                            (tau_g2, compressed_output),
                            (start_chunk, end_chunk),
                            &mut g2,
                        )
                        .expect("could not check ratios for Tau G2");
                        trace!("tau g2 verification successful");
                    });

                    t.spawn(|_| {
                        let _enter = span.enter();
                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                        check_elements_are_non_zero_and_in_prime_order_subgroup::<E::G1Affine>(
                            (alpha_g1, compressed_output),
                            (start_chunk, end_chunk),
                            &mut g1,
                        )
                        .expect("could not check ratios for Alpha G1");

                        trace!("alpha g1 verification successful");
                    });

                    t.spawn(|_| {
                        let _enter = span.enter();
                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                        check_elements_are_non_zero_and_in_prime_order_subgroup::<E::G1Affine>(
                            (beta_g1, compressed_output),
                            (start_chunk, end_chunk),
                            &mut g1,
                        )
                        .expect("could not check ratios for Beta G1");

                        trace!("beta g1 verification successful");
                    });
                });
            }
        });
        debug!("batch verification successful");

        Ok(())
    })?;

    info!("verification complete");
    Ok(())
}

/// Verifies that the accumulator was transformed correctly
/// given the `PublicKey` and the so-far hash of the accumulator.
/// This verifies the ratios in a given accumulator.
pub fn verify_ratios<E: PairingEngine>(
    (output, compressed_output, check_output_for_correctness): (
        &[u8],
        UseCompression,
        CheckForCorrectness,
    ),
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let span = info_span!("phase1-verify-ratios");
    let _enter = span.enter();

    info!("starting...");

    let (tau_g1, tau_g2, alpha_g1, beta_g1, _) = split_full(output, parameters, compressed_output);

    // Ensure that the initial conditions are correctly formed (first 2 elements)
    // We allocate a G1 vector of length 2 and re-use it for our G1 elements.
    // We keep the values of the Tau G1/G2 telements for later use.
    let (g1_check, g2_check) = {
        let after_g1 = read_initial_elements::<E::G1Affine>(
            tau_g1,
            compressed_output,
            check_output_for_correctness,
        )?;
        if after_g1[0] != E::G1Affine::prime_subgroup_generator() {
            return Err(VerificationError::InvalidGenerator(ElementType::TauG1).into());
        }
        let after_g2 = read_initial_elements::<E::G2Affine>(
            tau_g2,
            compressed_output,
            check_output_for_correctness,
        )?;
        if after_g2[0] != E::G2Affine::prime_subgroup_generator() {
            return Err(VerificationError::InvalidGenerator(ElementType::TauG2).into());
        }
        let g1_check = (after_g1[0], after_g1[1]);
        let g2_check = (after_g2[0], after_g2[1]);

        (g1_check, g2_check)
    };

    debug!("initial elements were computed correctly");

    // preallocate 2 vectors per batch
    // Ensure that the pairs are created correctly (we do this in chunks!)
    // load `batch_size` chunks on each iteration and perform the transformation
    iter_chunk(&parameters, |start, end| {
        debug!("verifying batch from {} to {}", start, end);
        let span = info_span!("batch", start, end);
        let _enter = span.enter();
        rayon::scope(|t| {
            let _enter = span.enter();
            t.spawn(|_| {
                let _enter = span.enter();
                let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                check_power_ratios::<E>(
                    (tau_g1, compressed_output, check_output_for_correctness),
                    (start, end),
                    &mut g1,
                    &g2_check,
                )
                .expect("could not check ratios for Tau G1");
                trace!("tau g1 verification successful");
            });

            if start < parameters.powers_length {
                // if the `end` would be out of bounds, then just process until
                // the end (this is necessary in case the last batch would try to
                // process more elements than available)
                let end = if start + parameters.batch_size > parameters.powers_length {
                    parameters.powers_length
                } else {
                    end
                };

                rayon::scope(|t| {
                    let _enter = span.enter();
                    t.spawn(|_| {
                        let _enter = span.enter();
                        let mut g2 = vec![E::G2Affine::zero(); parameters.batch_size];
                        check_power_ratios_g2::<E>(
                            (tau_g2, compressed_output, check_output_for_correctness),
                            (start, end),
                            &mut g2,
                            &g1_check,
                        )
                        .expect("could not check ratios for Tau G2");
                        trace!("tau g2 verification successful");
                    });

                    t.spawn(|_| {
                        let _enter = span.enter();
                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                        check_power_ratios::<E>(
                            (alpha_g1, compressed_output, check_output_for_correctness),
                            (start, end),
                            &mut g1,
                            &g2_check,
                        )
                        .expect("could not check ratios for Alpha G1");
                        trace!("alpha g1 verification successful");
                    });

                    t.spawn(|_| {
                        let _enter = span.enter();
                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                        check_power_ratios::<E>(
                            (beta_g1, compressed_output, check_output_for_correctness),
                            (start, end),
                            &mut g1,
                            &g2_check,
                        )
                        .expect("could not check ratios for Beta G1");
                        trace!("beta g1 verification successful");
                    });
                });
            }
        });

        debug!("chunk verification successful");

        Ok(())
    })?;

    info!("verification complete");
    Ok(())
}

/// Verifies that the accumulator was transformed correctly
/// given the `PublicKey` and the so-far hash of the accumulator.
/// This verifies a single chunk and checks only that the points
/// are not zero and that they're in the prime order subgroup.
pub fn combine<E: PairingEngine>(
    inputs: &[(&[u8], UseCompression)],
    (output, compressed_output): (&mut [u8], UseCompression),
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let span = info_span!("phase1-combine");
    let _enter = span.enter();

    info!("starting...");

    for (chunk_index, (input, compressed_input)) in inputs.iter().enumerate() {
        let chunk_parameters = parameters.specialize_to_chunk(
            parameters.contribution_mode,
            chunk_index,
            parameters.chunk_size,
        );
        let input = *input;
        let compressed_input = *compressed_input;

        let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
            split(input, &chunk_parameters, compressed_input);

        let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) =
            split_at_chunk_mut(output, &chunk_parameters, compressed_output);

        let start = chunk_index * chunk_parameters.chunk_size;
        let end = (chunk_index + 1) * chunk_parameters.chunk_size;
        debug!("combining chunk from {} to {}", start, end);
        let span = info_span!("batch", start, end);
        let _enter = span.enter();
        rayon::scope(|t| {
            let _enter = span.enter();
            t.spawn(|_| {
                let _enter = span.enter();
                let elements: Vec<E::G1Affine> = in_tau_g1
                    .read_batch(compressed_input, CheckForCorrectness::No)
                    .expect("should have read batch");
                tau_g1
                    .write_batch(&elements, compressed_output)
                    .expect("should have written batch");
                trace!("tau g1 combining for chunk {} successful", chunk_index);
            });

            if start < chunk_parameters.powers_length {
                rayon::scope(|t| {
                    let _enter = span.enter();
                    t.spawn(|_| {
                        let _enter = span.enter();
                        let elements: Vec<E::G2Affine> = in_tau_g2
                            .read_batch(compressed_input, CheckForCorrectness::No)
                            .expect("should have read batch");
                        tau_g2
                            .write_batch(&elements, compressed_output)
                            .expect("should have written batch");
                        trace!("tau g2 combining for chunk {} successful", chunk_index);
                    });

                    t.spawn(|_| {
                        let _enter = span.enter();
                        let elements: Vec<E::G1Affine> = in_alpha_g1
                            .read_batch(compressed_input, CheckForCorrectness::No)
                            .expect("should have read batch");
                        alpha_g1
                            .write_batch(&elements, compressed_output)
                            .expect("should have written batch");
                        trace!("alpha g1 combining for chunk {} successful", chunk_index);
                    });

                    t.spawn(|_| {
                        let _enter = span.enter();
                        let elements: Vec<E::G1Affine> = in_beta_g1
                            .read_batch(compressed_input, CheckForCorrectness::No)
                            .expect("should have read batch");
                        beta_g1
                            .write_batch(&elements, compressed_output)
                            .expect("should have written batch");
                        trace!("beta g1 combining for chunk {} successful", chunk_index);
                    });
                });
            }

            if chunk_index == 0 {
                let element: E::G2Affine = (&*in_beta_g2)
                    .read_element(compressed_input, CheckForCorrectness::No)
                    .expect("should have read element");
                beta_g2
                    .write_element(&element, compressed_output)
                    .expect("should have written element");
                trace!("beta g2 combining for chunk {} successful", chunk_index);
            }
        });

        debug!("chunk {} processing successful", chunk_index);
    }

    info!("combining complete");
    Ok(())
}

/// Serializes all the provided elements to the output buffer
#[allow(unused)]
pub fn serialize<E: PairingEngine>(
    elements: AccumulatorElementsRef<E>,
    output: &mut [u8],
    compressed: UseCompression,
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) = elements;
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split_mut(output, parameters, compressed);

    tau_g1.write_batch(&in_tau_g1, compressed)?;
    tau_g2.write_batch(&in_tau_g2, compressed)?;
    alpha_g1.write_batch(&in_alpha_g1, compressed)?;
    beta_g1.write_batch(&in_beta_g1, compressed)?;
    beta_g2.write_element(in_beta_g2, compressed)?;

    Ok(())
}

/// warning, only use this on machines which have enough memory to load
/// the accumulator in memory
pub fn deserialize<E: PairingEngine>(
    input: &[u8],
    compressed: UseCompression,
    check_input_for_correctness: CheckForCorrectness,
    parameters: &CeremonyParams<E>,
) -> Result<AccumulatorElements<E>> {
    // get an immutable reference to the input chunks
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
        split(&input, parameters, compressed);

    // deserialize each part of the buffer separately
    let tau_g1 = in_tau_g1.read_batch(compressed, check_input_for_correctness)?;
    let tau_g2 = in_tau_g2.read_batch(compressed, check_input_for_correctness)?;
    let alpha_g1 = in_alpha_g1.read_batch(compressed, check_input_for_correctness)?;
    let beta_g1 = in_beta_g1.read_batch(compressed, check_input_for_correctness)?;
    let beta_g2 = (&*in_beta_g2).read_element(compressed, check_input_for_correctness)?;

    Ok((tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2))
}

/// Reads an input buffer and a secret key **which must be destroyed after this function is executed**.
pub fn decompress<E: PairingEngine>(
    input: &[u8],
    check_input_for_correctness: CheckForCorrectness,
    output: &mut [u8],
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let compressed_input = UseCompression::Yes;
    let compressed_output = UseCompression::No;
    // get an immutable reference to the compressed input chunks
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, mut in_beta_g2) =
        split(&input, parameters, compressed_input);

    // get mutable refs to the decompressed outputs
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) =
        split_mut(output, parameters, compressed_output);

    // decompress beta_g2
    {
        // get the compressed element
        let beta_g2_el = in_beta_g2
            .read_element::<E::G2Affine>(compressed_input, check_input_for_correctness)?;
        // write it back decompressed
        beta_g2.write_element(&beta_g2_el, compressed_output)?;
    }

    let (g1_els_in_chunk, other_els_in_chunk) = parameters.chunk_element_sizes();
    // load `batch_size` chunks on each iteration and decompress them
    // decompress each element
    rayon::scope(|t| {
        t.spawn(|_| {
            decompress_buffer::<E::G1Affine>(
                tau_g1,
                in_tau_g1,
                (0, g1_els_in_chunk),
                check_input_for_correctness,
            )
            .expect("could not decompress the TauG1 elements")
        });
        if other_els_in_chunk > 0 {
            rayon::scope(|t| {
                t.spawn(|_| {
                    decompress_buffer::<E::G2Affine>(
                        tau_g2,
                        in_tau_g2,
                        (0, other_els_in_chunk),
                        check_input_for_correctness,
                    )
                    .expect("could not decompress the TauG2 elements")
                });
                t.spawn(|_| {
                    decompress_buffer::<E::G1Affine>(
                        alpha_g1,
                        in_alpha_g1,
                        (0, other_els_in_chunk),
                        check_input_for_correctness,
                    )
                    .expect("could not decompress the AlphaG1 elements")
                });
                t.spawn(|_| {
                    decompress_buffer::<E::G1Affine>(
                        beta_g1,
                        in_beta_g1,
                        (0, other_els_in_chunk),
                        check_input_for_correctness,
                    )
                    .expect("could not decompress the BetaG1 elements")
                });
            });
        }
    });

    Ok(())
}

/// Reads an input buffer and a secret key **which must be destroyed after this function is executed**.
/// It then generates 2^(N+1) -1 powers of tau (tau is stored inside the secret key).
/// Finally, each group element read from the input is multiplied by the corresponding power of tau depending
/// on its index and maybe some extra coefficient, and is written to the output buffer.
pub fn contribute<E: PairingEngine>(
    input: (&[u8], UseCompression, CheckForCorrectness),
    output: (&mut [u8], UseCompression),
    key: &PrivateKey<E>,
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let span = info_span!("phase1-contribute");
    let _enter = span.enter();

    info!("starting...");

    let (input, compressed_input, check_input_for_correctness) = (input.0, input.1, input.2);
    let (output, compressed_output) = (output.0, output.1);
    // get an immutable reference to the input chunks
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, mut in_beta_g2) =
        split(&input, parameters, compressed_input);

    // get mutable refs to the outputs
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) =
        split_mut(output, parameters, compressed_output);

    // write beta_g2
    {
        // get the element
        let mut beta_g2_el = in_beta_g2
            .read_element::<E::G2Affine>(compressed_input, check_input_for_correctness)?;
        // multiply it by the key's beta
        beta_g2_el = beta_g2_el.mul(key.beta).into_affine();
        // write it back
        beta_g2.write_element(&beta_g2_el, compressed_output)?;
    }

    iter_chunk(&parameters, |start, end| {
        let (start_chunk, end_chunk) = match parameters.contribution_mode {
            ContributionMode::Chunked => (
                start - parameters.chunk_index * parameters.chunk_size,
                end - parameters.chunk_index * parameters.chunk_size,
            ),
            ContributionMode::Full => (start, end),
        };
        // load `batch_size` chunks on each iteration and perform the transformation
        debug!("contributing to chunk from {} to {}", start, end);
        let span = info_span!("batch", start, end);
        let _enter = span.enter();
        rayon::scope(|t| {
            let _enter = span.enter();
            t.spawn(|_| {
                let _enter = span.enter();
                // generate powers from `start` to `end` (e.g. [0,4) then [4, 8) etc.)
                let powers = generate_powers_of_tau::<E>(&key.tau, start, end);
                trace!("generated powers of tau");

                // raise each element from the input buffer to the powers of tau
                // and write the updated value (without allocating) to the
                // output buffer
                rayon::scope(|t| {
                    let _enter = span.enter();
                    t.spawn(|_| {
                        let _enter = span.enter();
                        apply_powers::<E::G1Affine>(
                            (tau_g1, compressed_output),
                            (in_tau_g1, compressed_input, check_input_for_correctness),
                            (start_chunk, end_chunk),
                            &powers,
                            None,
                        )
                        .expect("could not apply powers of tau to the TauG1 elements");
                        trace!("applied powers to tau g1 elements");
                    });
                    if start < parameters.powers_length {
                        let end = if start + parameters.batch_size > parameters.powers_length {
                            parameters.powers_length
                        } else {
                            end
                        };
                        let (start_chunk, end_chunk) = match parameters.contribution_mode {
                            ContributionMode::Chunked => (
                                start - parameters.chunk_index * parameters.chunk_size,
                                end - parameters.chunk_index * parameters.chunk_size,
                            ),
                            ContributionMode::Full => (start, end),
                        };
                        rayon::scope(|t| {
                            let _enter = span.enter();
                            t.spawn(|_| {
                                let _enter = span.enter();
                                apply_powers::<E::G2Affine>(
                                    (tau_g2, compressed_output),
                                    (in_tau_g2, compressed_input, check_input_for_correctness),
                                    (start_chunk, end_chunk),
                                    &powers,
                                    None,
                                )
                                .expect("could not apply powers of tau to the TauG2 elements");
                                trace!("applied powers to tau g2 elements");
                            });
                            t.spawn(|_| {
                                let _enter = span.enter();
                                apply_powers::<E::G1Affine>(
                                    (alpha_g1, compressed_output),
                                    (in_alpha_g1, compressed_input, check_input_for_correctness),
                                    (start_chunk, end_chunk),
                                    &powers,
                                    Some(&key.alpha),
                                )
                                .expect("could not apply powers of tau to the AlphaG1 elements");
                                trace!("applied powers to alpha g1 elements");
                            });
                            t.spawn(|_| {
                                let _enter = span.enter();
                                apply_powers::<E::G1Affine>(
                                    (beta_g1, compressed_output),
                                    (in_beta_g1, compressed_input, check_input_for_correctness),
                                    (start_chunk, end_chunk),
                                    &powers,
                                    Some(&key.beta),
                                )
                                .expect("could not apply powers of tau to the BetaG1 elements");
                                trace!("applied powers to beta g1 elements");
                            });
                        });
                    }
                });
            });
        });

        debug!("batch contribution successful");

        Ok(())
    })?;

    info!("done contributing");

    Ok(())
}

/// Takes a compressed input buffer and decompresses it
fn decompress_buffer<C: AffineCurve>(
    output: &mut [u8],
    input: &[u8],
    (start, end): (usize, usize),
    check_input_for_correctness: CheckForCorrectness,
) -> Result<()> {
    let in_size = buffer_size::<C>(UseCompression::Yes);
    let out_size = buffer_size::<C>(UseCompression::No);
    // read the compressed input
    let elements = input[start * in_size..end * in_size]
        .read_batch::<C>(UseCompression::Yes, check_input_for_correctness)?;
    // write it back uncompressed
    output[start * out_size..end * out_size].write_batch(&elements, UseCompression::No)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use test_helpers::random_point_vec;
    use zexe_algebra::bls12_377::Bls12_377;

    #[test]
    fn test_decompress_buffer() {
        test_decompress_buffer_curve::<<Bls12_377 as PairingEngine>::G1Affine>();
        test_decompress_buffer_curve::<<Bls12_377 as PairingEngine>::G2Affine>();
    }

    fn test_decompress_buffer_curve<C: AffineCurve>() {
        // generate some random points
        let mut rng = thread_rng();
        let num_els = 10;
        let elements: Vec<C> = random_point_vec(num_els, &mut rng);
        // write them as compressed
        let len = num_els * buffer_size::<C>(UseCompression::Yes);
        let mut input = vec![0; len];
        input.write_batch(&elements, UseCompression::Yes).unwrap();

        // allocate the decompressed buffer
        let len = num_els * buffer_size::<C>(UseCompression::No);
        let mut out = vec![0; len];
        // perform the decompression
        decompress_buffer::<C>(&mut out, &input, (0, num_els), CheckForCorrectness::No).unwrap();
        let deserialized = out
            .read_batch::<C>(UseCompression::No, CheckForCorrectness::No)
            .unwrap();
        // ensure they match
        assert_eq!(deserialized, elements);
    }
}

/// Takes a buffer, reads the group elements in it, exponentiates them to the
/// provided `powers` and maybe to the `coeff`, and then writes them back
fn apply_powers<C: AffineCurve>(
    (output, output_compressed): Output,
    (input, input_compressed, check_input_for_correctness): Input,
    (start, end): (usize, usize),
    powers: &[C::ScalarField],
    coeff: Option<&C::ScalarField>,
) -> Result<()> {
    let in_size = buffer_size::<C>(input_compressed);
    let out_size = buffer_size::<C>(output_compressed);
    // read the input
    let mut elements = &mut input[start * in_size..end * in_size]
        .read_batch::<C>(input_compressed, check_input_for_correctness)?;
    // calculate the powers
    batch_exp(&mut elements, &powers[..end - start], coeff)?;
    // write back
    output[start * out_size..end * out_size].write_batch(&elements, output_compressed)?;

    Ok(())
}

/// Splits the full buffer in 5 non overlapping mutable slice.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
fn split_mut<'a, E: PairingEngine>(
    buf: &'a mut [u8],
    parameters: &'a CeremonyParams<E>,
    compressed: UseCompression,
) -> SplitBufMut<'a> {
    let (g1_els_in_chunk, other_els_in_chunk) = parameters.chunk_element_sizes();
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    // leave the first 64 bytes for the hash
    let (_, others) = buf.split_at_mut(parameters.hash_size);
    let (tau_g1, others) = others.split_at_mut(g1_size * g1_els_in_chunk);
    let (tau_g2, others) = others.split_at_mut(g2_size * other_els_in_chunk);
    let (alpha_g1, others) = others.split_at_mut(g1_size * other_els_in_chunk);
    let (beta_g1, beta_g2) = others.split_at_mut(g1_size * other_els_in_chunk);
    // we take up to g2_size for beta_g2, since there might be other
    // elements after it at the end of the buffer
    (tau_g1, tau_g2, alpha_g1, beta_g1, &mut beta_g2[0..g2_size])
}

/// Splits the full buffer in 5 non overlapping mutable slice for a given chunk and batch size.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
fn split_at_chunk_mut<'a, E: PairingEngine>(
    buf: &'a mut [u8],
    parameters: &'a CeremonyParams<E>,
    compressed: UseCompression,
) -> SplitBufMut<'a> {
    let (g1_els_in_chunk, other_els_in_chunk) = parameters.chunk_element_sizes();
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    let buf_to_chunk = |buf: &'a mut [u8], element_size: usize, is_other: bool| -> &'a mut [u8] {
        if is_other && other_els_in_chunk == 0 {
            return &mut [];
        }
        let els_in_chunk = if is_other {
            other_els_in_chunk
        } else {
            g1_els_in_chunk
        };
        let start = parameters.chunk_index * parameters.chunk_size * element_size;
        let end = start + els_in_chunk * element_size;
        &mut buf[start..end]
    };

    // leave the first 64 bytes for the hash
    let (_, others) = buf.split_at_mut(parameters.hash_size);
    let (tau_g1, others) = others.split_at_mut(g1_size * parameters.powers_g1_length);
    let (tau_g2, others) = others.split_at_mut(g2_size * parameters.powers_length);
    let (alpha_g1, others) = others.split_at_mut(g1_size * parameters.powers_length);
    let (beta_g1, beta_g2) = others.split_at_mut(g1_size * parameters.powers_length);
    // we take up to g2_size for beta_g2, since there might be other
    // elements after it at the end of the buffer
    (
        buf_to_chunk(tau_g1, g1_size, false),
        buf_to_chunk(tau_g2, g2_size, true),
        buf_to_chunk(alpha_g1, g1_size, true),
        buf_to_chunk(beta_g1, g1_size, true),
        &mut beta_g2[0..g2_size],
    )
}

/// Splits the full buffer in 5 non overlapping immutable slice.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
fn split<'a, E: PairingEngine>(
    buf: &'a [u8],
    parameters: &CeremonyParams<E>,
    compressed: UseCompression,
) -> SplitBuf<'a> {
    let (g1_els_in_chunk, other_els_in_chunk) = parameters.chunk_element_sizes();
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    let (_, others) = buf.split_at(parameters.hash_size);
    let (tau_g1, others) = others.split_at(g1_size * g1_els_in_chunk);
    let (tau_g2, others) = others.split_at(g2_size * other_els_in_chunk);
    let (alpha_g1, others) = others.split_at(g1_size * other_els_in_chunk);
    let (beta_g1, beta_g2) = others.split_at(g1_size * other_els_in_chunk);
    // we take up to g2_size for beta_g2, since there might be other
    // elements after it at the end of the buffer
    (tau_g1, tau_g2, alpha_g1, beta_g1, &beta_g2[0..g2_size])
}

/// Splits the full buffer in 5 non overlapping immutable slice.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
fn split_full<'a, E: PairingEngine>(
    buf: &'a [u8],
    parameters: &CeremonyParams<E>,
    compressed: UseCompression,
) -> SplitBuf<'a> {
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    let (_, others) = buf.split_at(parameters.hash_size);
    let (tau_g1, others) = others.split_at(g1_size * parameters.powers_g1_length);
    let (tau_g2, others) = others.split_at(g2_size * parameters.powers_length);
    let (alpha_g1, others) = others.split_at(g1_size * parameters.powers_length);
    let (beta_g1, beta_g2) = others.split_at(g1_size * parameters.powers_length);
    // we take up to g2_size for beta_g2, since there might be other
    // elements after it at the end of the buffer
    (tau_g1, tau_g2, alpha_g1, beta_g1, &beta_g2[0..g2_size])
}
