use alloc::vec::Vec;

use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::{SolCall, SolType};
use openzeppelin_stylus::access::ownable::Ownable;
use stylus_sdk::{
    alloy_sol_types::sol,
    call::call,
    crypto::keccak,
    evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageMap, StorageU256},
};

use crate::utils::{
    eip712::{Eip712, Eip712Params},
    errors::{AlreadyInitialized, CallError, Errors, InvalidPlatformSignature},
    solidity::isAuthorizedCall,
};

sol! {
    event CcuPushed(address indexed user, bytes32 channelId, uint256 totalConsumption);
}

struct ConsumptionParam;

impl Eip712Params for ConsumptionParam {
    // Static fields
    const NAME: &'static str = "ChannelConsumption";
    const VERSION: &'static str = "0.0.1";
}

/// Define the global contract storage
#[storage]
#[entrypoint]
pub struct ChannelConsumptionContract {
    // The user activity storage (user => UserConsumption)
    user_consumptions: StorageMap<Address, StorageU256>,
    // Some general configurations
    nutty_content_id: StorageU256,
    content_registry: StorageAddress,
    // The total tracked consumption
    total_consumption: StorageU256,
    // The ownable borrowing
    #[borrow]
    ownable: Ownable,
    #[borrow]
    eip712: Eip712<ConsumptionParam>,
}

/// Some internal helpers
impl ChannelConsumptionContract {
    /// Check that the validator has the right roles
    pub fn _check_validator_role(&mut self, validator: Address) -> Result<(), Errors> {
        // Ensure the signer has the interaction validator roles for this content)
        let content_registry = self.content_registry.get();
        let has_role = call_helper::<isAuthorizedCall>(
            self,
            content_registry,
            (self.nutty_content_id.get(), validator),
        )
        .map_err(|_| Errors::CallError(CallError {}))?;

        // Return the right state depending on the output
        if has_role._0 {
            Ok(())
        } else {
            Err(Errors::InvalidPlatformSignature(
                InvalidPlatformSignature {},
            ))
        }
    }
}

/// Declare that `ContentConsumptionContract` is a contract with the following external methods.
#[public]
#[inherit(Ownable, Eip712<ConsumptionParam>)]
impl ChannelConsumptionContract {
    /* -------------------------------------------------------------------------- */
    /*                                 Constructor                                */
    /* -------------------------------------------------------------------------- */

    /// Initialize the contract with an owner.
    /// TODO: No constructor possible atm, so going with init method called during contract creation via multicall
    /// See: https://github.com/OffchainLabs/stylus-sdk-rs/issues/99
    #[selector(name = "initialize")]
    pub fn initialize(
        &mut self,
        owner: Address,
        nutty_content_id: U256,
        content_registry: Address,
    ) -> Result<(), Errors> {
        // Ensure that the contract has not been initialized
        if !self.ownable.owner().is_zero() {
            return Err(Errors::AlreadyInitialized(AlreadyInitialized {}));
        }

        // Init our owner
        self.ownable._transfer_ownership(owner);

        // Init our global config
        self.nutty_content_id.set(nutty_content_id);
        self.content_registry.set(content_registry);

        // Return the success
        Ok(())
    }

    /* -------------------------------------------------------------------------- */
    /*                                  CCU push                                  */
    /* -------------------------------------------------------------------------- */

    /// Push a new consumption for a given platform
    #[selector(name = "pushCcu")]
    pub fn push_ccu(
        &mut self,
        channel_id: FixedBytes<32>,
        added_consumption: U256,
        deadline: U256,
        v: u8,
        r: FixedBytes<32>,
        s: FixedBytes<32>,
    ) -> Result<(), Errors> {
        // No need to check that te platform exists, as the consumption will be rejected
        //  if the recovered address is zero, and if the owner doesn't match the recovered address

        // Rebuild the signed data
        let user = msg::sender();
        let struct_hash = keccak(
            <sol! { (bytes32, address, bytes32, uint256, uint256) }>::abi_encode(&(
                keccak(b"ValidateConsumption(address user,bytes32 channelId,uint256 addedConsumption,uint256 deadline)").0,
                user,
                channel_id.0,
                added_consumption,
                deadline,
            )),
        );

        // Do an ecdsa recovery check on the signature
        let recovered_address = self
            .eip712
            .recover_typed_data_signer(struct_hash, v, r, s)?;

        // Ensure the signer has the interaction validator roles for this content)
        let check_result = self._check_validator_role(recovered_address);
        if check_result.is_err() {
            // Early exit cause it's failing otherwise
            // Always passing the same error to avoid leaking information
            return Ok(());
        }

        // Get the current state
        let mut storage_ptr = self.user_consumptions.setter(user);

        let total_consumption = storage_ptr.get() + added_consumption;

        // Emit the event
        evm::log(CcuPushed {
            user,
            channelId: channel_id,
            totalConsumption: total_consumption,
        });

        // Update the ccu amount
        storage_ptr.set(total_consumption);

        // Update the whole total consumption
        self.total_consumption
            .set(self.total_consumption.get() + added_consumption);

        // Return the success
        Ok(())
    }

    /// Get the total consumption of a user
    #[selector(name = "getUserConsumption")]
    pub fn get_user_consumption(
        &self,
        user: Address,
    ) -> Result<U256, Errors> {
        // Return the consumption
        Ok(self.user_consumptions.get(user))
    }

    /// Get the total consumption handled by the contract
    #[selector(name = "getTotalConsumption")]
    pub fn get_total_consumption(&self) -> Result<U256, Errors> {
        Ok(self.total_consumption.get())
    }
}

/// Simple helper to perform call to another smart contract
pub fn call_helper<C: SolCall>(
    storage: &mut impl TopLevelStorage,
    address: Address,
    args: <C::Arguments<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>> {
    let calldata = C::new(args).abi_encode();
    let res = call(storage, address, &calldata)?;
    C::abi_decode_returns(&res, false).map_err(|_| b"decoding error".to_vec())
}
