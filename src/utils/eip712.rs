use core::marker::PhantomData;

use inkmate_common::crypto::ecrecover::EcRecoverTrait;
use stylus_sdk::{
    alloy_primitives::{Address, FixedBytes, B256, U256, U64},
    alloy_sol_types::sol,
    block, contract,
    crypto::keccak,
    prelude::*,
    storage::{StorageB256, StorageU64},
};

use crate::utils::{
    errors::{EcRecoverError, Errors},
    signature::PrecompileEcRecover,
};

pub trait Eip712Params {
    // Name of the contract
    const NAME: &'static str;
    const VERSION: &'static str;
}

// Define the global owned contract storage
#[storage]
pub struct Eip712<T: Eip712Params> {
    cached_chain_id: StorageU64,
    cached_domain_separator: StorageB256,
    phantom: PhantomData<T>,
}

impl<T: Eip712Params> Eip712<T> {
    // Initialise the Eip712 contract (build initial cached domain separator)
    pub fn initialize(&mut self) {
        let initial_domain_separator = Eip712::<T>::compute_domain_separator();
        self.cached_chain_id.set(U64::from(block::chainid()));
        self.cached_domain_separator.set(initial_domain_separator);
    }

    /// Compute a new domain separator
    fn compute_domain_separator() -> B256 {

        keccak(
            <sol! { (bytes32, bytes32, bytes32, uint256, address) }>::encode(&(
                keccak("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").0,
                keccak(T::NAME.as_bytes()).0,
                keccak(T::VERSION.as_bytes()).0,
                U256::from(block::chainid()),
                contract::address(),
            )),
        )
    }

    /// Get the current domain separator
    /// Mutable since, if not cached, it could compute it and store it in cache
    pub fn domain_separator(&mut self) -> Result<B256, Errors> {
        // If the chain id is the same, return the cached domain separator
        if block::chainid() == self.cached_chain_id.get().to::<u64>() {
            Ok(self.cached_domain_separator.get())
        } else {
            // Otherwise, update it
            let domain_separator = Eip712::<T>::compute_domain_separator();
            // Updated cached infos
            self.cached_chain_id.set(U64::from(block::chainid()));
            self.cached_domain_separator.set(domain_separator);
            // And read it
            Ok(domain_separator)
        }
    }

    /// Recovery the typed data signer
    /// Mutable since, if domain separator not cached, it could recompute  it and store it in cache
    pub fn recover_typed_data_signer(
        &mut self,
        struct_hash: B256,
        v: u8,
        r: FixedBytes<32>,
        s: FixedBytes<32>,
    ) -> Result<Address, Errors> {
        // Rebuild the digest input
        let mut digest_input = [0u8; 2 + 32 + 32];
        digest_input[0] = 0x19;
        digest_input[1] = 0x01;
        digest_input[2..34].copy_from_slice(&self.domain_separator()?[..]);
        digest_input[34..66].copy_from_slice(&struct_hash[..]);

        // TODO the ecdsa recovery we need:

        // Do an ecdsa recovery check on the signature
        let recovered_address = Address::from_slice(
            &PrecompileEcRecover::ecrecover(&keccak(digest_input), v, &r.0, &s.0)
                .map_err(|_| Errors::EcRecoverError(EcRecoverError {}))?,
        );

        // Return the recovered address
        Ok(recovered_address)
    }
}

#[public]
impl<T: Eip712Params> Eip712<T> {
    /// Get the current domain separator
    #[selector(name = "domainSeparator")]
    pub fn read_domain_separator(&self) -> Result<FixedBytes<32>, Errors> {
        Ok(Eip712::<T>::compute_domain_separator())
    }
}
