// Copyright (c) 2019-2026 Provable Inc.
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

impl<A: Aleo> Record<A, Plaintext<A>> {
    /// Returns the entry from the given path.
    pub fn find<A0: Into<Access<A>> + Clone + Debug>(&self, path: &[A0]) -> Result<Entry<A, Plaintext<A>>> {
        // Check the nonce before the `owner`: comparing `Access` values ejects them, and ejecting `_nonce` halts.
        if let [access] = path
            && let Access::Member(identifier) = access.clone().into()
            && identifier == Identifier::constant(console::Identifier::record_nonce()?)
        {
            return Ok(Entry::Private(Plaintext::from(Literal::Group(self.nonce.clone()))));
        }
        // If the path is of length one, check if the path is requesting the `owner`.
        if path.len() == 1 && path[0].clone().into() == Access::Member(Identifier::from_str("owner")?) {
            return Ok(self.owner.to_entry());
        }

        // Ensure the path is not empty.
        if let Some((first, rest)) = path.split_first() {
            let first = match first.clone().into() {
                Access::Member(identifier) => identifier,
                Access::Index(_) => bail!("Attempted to index into a record"),
            };
            // Retrieve the top-level entry.
            match self.data.get(&first) {
                Some(entry) => match rest.is_empty() {
                    // If the remaining path is empty, return the top-level entry.
                    true => Ok(entry.clone()),
                    // Otherwise, recursively call `find` on the top-level entry.
                    false => entry.find(rest),
                },
                None => bail!("Record entry `{first}` not found."),
            }
        } else {
            bail!("Attempted to find record entry with an empty path.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;

    type CurrentNetwork = <Circuit as Environment>::Network;

    #[test]
    fn test_find_nonce_and_owner() -> Result<()> {
        let console_record = console::Record::<CurrentNetwork, console::Plaintext<CurrentNetwork>>::from_str(
            r"{
    owner: aleo14tlamssdmg3d0p5zmljma573jghe2q9n6wz29qf36re2glcedcpqfg4add.private,
    amount: 5u64.private,
    _nonce: 2293253577170800572742339369209137467208538700597121244293392265726446806023group.public
}",
        )?;
        let record = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, console_record.clone());

        let nonce = record.find(&[Access::constant(console::Access::Member(console::Identifier::record_nonce()?))])?;
        match nonce {
            Entry::Private(Plaintext::Literal(Literal::Group(nonce), _)) => {
                assert_eq!(*console_record.nonce(), nonce.eject_value())
            }
            _ => bail!("Expected the record nonce to be a private group entry"),
        }

        let owner =
            record.find(&[Access::constant(console::Access::Member(console::Identifier::from_str("owner")?))])?;
        match owner {
            Entry::Private(Plaintext::Literal(Literal::Address(owner), _)) => {
                assert_eq!(**console_record.owner(), owner.eject_value())
            }
            _ => bail!("Expected the record owner to be a private address entry"),
        }
        Ok(())
    }
}
