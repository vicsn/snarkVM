// Copyright 2024 Aleo Network Foundation
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

impl<N: Network> Serialize for Header<N> {
    /// Serializes the header to a JSON-string or buffer.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut header = serializer.serialize_struct("Header", 7)?;
                header.serialize_field("previous_state_root", &self.previous_state_root)?;
                header.serialize_field("transactions_root", &self.transactions_root)?;
                header.serialize_field("finalize_root", &self.finalize_root)?;
                header.serialize_field("ratifications_root", &self.ratifications_root)?;
                header.serialize_field("solutions_root", &self.solutions_root)?;
                header.serialize_field("subdag_root", &self.subdag_root)?;
                header.serialize_field("metadata", &self.metadata)?;
                header.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Header<N> {
    /// Deserializes the header from a JSON-string or buffer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                let mut header = serde_json::Value::deserialize(deserializer)?;
                Ok(Self::from(
                    DeserializeExt::take_from_value::<D>(&mut header, "previous_state_root")?,
                    DeserializeExt::take_from_value::<D>(&mut header, "transactions_root")?,
                    DeserializeExt::take_from_value::<D>(&mut header, "finalize_root")?,
                    DeserializeExt::take_from_value::<D>(&mut header, "ratifications_root")?,
                    DeserializeExt::take_from_value::<D>(&mut header, "solutions_root")?,
                    DeserializeExt::take_from_value::<D>(&mut header, "subdag_root")?,
                    DeserializeExt::take_from_value::<D>(&mut header, "metadata")?,
                )
                .map_err(de::Error::custom)?)
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "block header"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_json() -> Result<()> {
        let rng = &mut TestRng::default();

        for expected in [crate::header::test_helpers::sample_block_header(rng)].into_iter() {
            // Serialize
            let expected_string = &expected.to_string();
            let candidate_string = serde_json::to_string(&expected)?;

            // Deserialize
            assert_eq!(expected, Header::from_str(expected_string)?);
            assert_eq!(expected, serde_json::from_str(&candidate_string)?);
        }
        Ok(())
    }

    #[test]
    fn test_bincode() -> Result<()> {
        let rng = &mut TestRng::default();

        for expected in [crate::header::test_helpers::sample_block_header(rng)].into_iter() {
            // Serialize
            let expected_bytes = expected.to_bytes_le()?;
            let expected_bytes_with_size_encoding = bincode::serialize(&expected)?;
            assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

            // Deserialize
            assert_eq!(expected, Header::read_le(&expected_bytes[..])?);
            assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..])?);
        }
        Ok(())
    }
}
