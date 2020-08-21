use snark_utils::{ElementType, UseCompression};
use std::marker::PhantomData;
use zexe_algebra::{ConstantSerializedSize, PairingEngine};

/// The sizes of the group elements of a curve
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct CurveParams<E> {
    /// Size of a G1 Element
    pub g1: usize,
    /// Size of a G2 Element
    pub g2: usize,
    /// Size of a compressed G1 Element
    pub g1_compressed: usize,
    /// Size of a compressed G2 Element
    pub g2_compressed: usize,
    engine_type: PhantomData<E>,
}

impl<E: PairingEngine> CurveParams<E> {
    pub fn new() -> CurveParams<E> {
        let g1_compressed = <E as PairingEngine>::G1Affine::SERIALIZED_SIZE;
        let g1_size = <E as PairingEngine>::G1Affine::UNCOMPRESSED_SIZE;

        let g2_compressed = <E as PairingEngine>::G2Affine::SERIALIZED_SIZE;
        let g2_size = <E as PairingEngine>::G2Affine::UNCOMPRESSED_SIZE;

        CurveParams {
            g1: g1_size,
            g2: g2_size,
            g1_compressed,
            g2_compressed,
            engine_type: PhantomData,
        }
    }
}

impl<E> CurveParams<E> {
    pub fn g1_size(&self, compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => self.g1_compressed,
            UseCompression::No => self.g1,
        }
    }

    pub fn g2_size(&self, compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => self.g2_compressed,
            UseCompression::No => self.g2,
        }
    }

    pub fn get_size(&self, element_type: ElementType, compression: UseCompression) -> usize {
        match element_type {
            ElementType::AlphaG1 | ElementType::BetaG1 | ElementType::TauG1 => {
                self.g1_size(compression)
            }
            ElementType::BetaG2 | ElementType::TauG2 => self.g2_size(compression),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The parameters used for the trusted setup ceremony
pub struct CeremonyParams<E> {
    /// The chunk index
    pub chunk_index: usize,
    /// The type of the curve being used
    pub curve: CurveParams<E>,
    /// The number of Powers of Tau G1 elements which will be accumulated
    pub powers_g1_length: usize,
    /// The number of Powers of Tau Alpha/Beta/G2 elements which will be accumulated
    pub powers_length: usize,
    /// The circuit size exponent (ie length will be 2^size), depends on the computation you want to support
    pub size: usize,
    /// The size of each chunk.
    pub batch_size: usize,
    // Size of the used public key
    pub public_key_size: usize,
    /// Total size of the accumulator used for the ceremony
    pub accumulator_size: usize,
    /// Total size of the contribution
    pub contribution_size: usize,
    /// Size of the hash of the previous contribution
    pub hash_size: usize,
}

impl<E: PairingEngine> CeremonyParams<E> {
    /// Constructs a new ceremony parameters object from the type of provided curve
    /// Panics if given batch_size = 0
    pub fn new_for_first_chunk(size: usize, batch_size: usize) -> Self {
        // create the curve
        let curve = CurveParams::<E>::new();
        Self::new_with_curve(0, curve, size, batch_size)
    }

    pub fn new(chunk_index: usize, size: usize, batch_size: usize) -> Self {
        // create the curve
        let curve = CurveParams::<E>::new();
        Self::new_with_curve(chunk_index, curve, size, batch_size)
    }

    /// Constructs a new ceremony parameters object from the directly provided curve with parameters
    /// Consider using the `new` method if you want to use one of the pre-implemented curves
    pub fn new_with_curve(
        chunk_index: usize,
        curve: CurveParams<E>,
        size: usize,
        batch_size: usize,
    ) -> Self {
        // assume we're using a 64 byte long hash function such as Blake
        let hash_size = 64;

        // 2^{size}
        let powers_length = 1 << size;
        // 2^{size+1} - 1
        let powers_g1_length = (powers_length << 1) - 1;

        let (g1_els_size, other_els_size) =
            chunk_element_sizes(batch_size, chunk_index, powers_g1_length, powers_length);

        let accumulator_size =
            // G1 Tau powers
            g1_els_size * curve.g1 +
            // G2 Tau Powers + Alpha Tau powers + Beta Tau powers
            other_els_size * (curve.g2 + (curve.g1 * 2)) +
            // Beta in G2
            curve.g2 +
            // Tau Single G1
            2*curve.g1 +
            // Tau Single G2
            2*curve.g2 +
            // Hash of the previous contribution
            hash_size;

        let public_key_size =
           // tau, alpha, beta in g2
           3 * curve.g2 +
           // (s1, s1*tau), (s2, s2*alpha), (s3, s3*beta) in g1
           6 * curve.g1;

        let contribution_size =
            // G1 Tau powers (compressed)
            g1_els_size * curve.g1_compressed +
            // G2 Tau Powers + Alpha Tau powers + Beta Tau powers (compressed)
            other_els_size * (curve.g2_compressed + (curve.g1_compressed * 2)) +
            // Beta in G2
            curve.g2_compressed +
            // Tau Single G1
            2 * curve.g1_compressed +
            // Tau Single G2
            2 * curve.g2_compressed +
            // Hash of the previous contribution
            hash_size +
            // The public key of the previous contributor
            public_key_size;

        Self {
            chunk_index,
            curve,
            size,
            batch_size,
            accumulator_size,
            public_key_size,
            contribution_size,
            hash_size,
            powers_length,
            powers_g1_length,
        }
    }

    /// Returns the length of the serialized accumulator depending on if it's compressed or not
    pub fn get_length(&self, compressed: UseCompression) -> usize {
        match compressed {
            UseCompression::Yes => self.contribution_size - self.public_key_size,
            UseCompression::No => self.accumulator_size,
        }
    }

    pub fn chunk_element_sizes(&self) -> (usize, usize) {
        chunk_element_sizes(
            self.batch_size,
            self.chunk_index,
            self.powers_g1_length,
            self.powers_length,
        )
    }

    pub fn specialize_to_chunk(&self, chunk_index: usize) -> Self {
        let mut params = self.clone();
        params.chunk_index = chunk_index;
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zexe_algebra::{Bls12_377, Bls12_381, BW6_761};

    #[test]
    fn params_sizes() {
        curve_params_test::<Bls12_377>(96, 192, 48, 96);
        curve_params_test::<Bls12_381>(96, 192, 48, 96);
        curve_params_test::<BW6_761>(192, 192, 96, 96);
    }

    fn curve_params_test<E: PairingEngine>(
        g1: usize,
        g2: usize,
        g1_compressed: usize,
        g2_compressed: usize,
    ) {
        let p = CurveParams::<E>::new();
        assert_eq!(p.g1, g1);
        assert_eq!(p.g2, g2);
        assert_eq!(p.g1_compressed, g1_compressed);
        assert_eq!(p.g2_compressed, g2_compressed);
    }
}

pub fn chunk_element_sizes(
    batch_size: usize,
    chunk_index: usize,
    powers_g1_length: usize,
    powers_length: usize,
) -> (usize, usize) {
    let (start, end) = (chunk_index * batch_size, (chunk_index + 1) * batch_size);
    let g1_els_in_chunk = if end > powers_g1_length {
        powers_g1_length - start
    } else {
        end - start
    };
    let other_els_in_chunk = if end > powers_length && start >= powers_length {
        0
    } else if end > powers_length {
        powers_length - start
    } else {
        end - start
    };

    (g1_els_in_chunk, other_els_in_chunk)
}
