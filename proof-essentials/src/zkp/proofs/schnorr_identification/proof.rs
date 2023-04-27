use super::{Parameters, Statement};
use crate::error::CryptoError;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_marlin::rng::FiatShamirRng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::UniformRand;
use digest::Digest;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub(crate) random_commit: C,
    pub(crate) opening: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify<D: Digest>(
        &self,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        fs_rng.absorb(&to_bytes![
            b"schnorr_identity",
            pp,
            statement,
            &self.random_commit
        ]?);

        let c = C::ScalarField::rand(fs_rng);

        if pp.mul(self.opening.into_repr()) + statement.mul(c.into_repr()) != self.random_commit {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification",
            )));
        }

        Ok(())
    }
}

impl <C>CanonicalSerialize for Proof<C> where C: ProjectiveCurve {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        let a = ProofAffine{
            random_commit: self.random_commit.into_affine(),
            opening: self.opening,
        };
        a.serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        let a = ProofAffine{
            random_commit: self.random_commit.into_affine(),
            opening: self.opening,
        };
        a.serialized_size()
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        let a = ProofAffine{
            random_commit: self.random_commit.into_affine(),
            opening: self.opening,
        };
        a.serialize_uncompressed(writer)
    }

    fn serialize_unchecked<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        let a = ProofAffine{
            random_commit: self.random_commit.into_affine(),
            opening: self.opening,
        };
        a.serialize_unchecked(writer)
    }

    fn uncompressed_size(&self) -> usize {
        let a = ProofAffine{
            random_commit: self.random_commit.into_affine(),
            opening: self.opening,
        };
        a.uncompressed_size()
    }
}

impl <C>CanonicalDeserialize for Proof<C> where C: ProjectiveCurve {
    fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        let a: ProofAffine<C::Affine> = CanonicalDeserialize::deserialize(reader)?;
        Ok(Proof{
            random_commit: a.random_commit.into_projective(),
            opening: a.opening
        })
    }

    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        let a: ProofAffine<C::Affine> = CanonicalDeserialize::deserialize_uncompressed(reader)?;
        Ok(Proof{
            random_commit: a.random_commit.into_projective(),
            opening: a.opening
        })
    }

    fn deserialize_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        let a: ProofAffine<C::Affine> = CanonicalDeserialize::deserialize_unchecked(reader)?;
        Ok(Proof{
            random_commit: a.random_commit.into_projective(),
            opening: a.opening
        })
    }
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ProofAffine<C>
where C: AffineCurve
{
    pub(crate) random_commit: C,
    pub(crate) opening: C::ScalarField,
}