use crate::primitives::{verkle_db::VerkleDatabaseRef, Address};
use crate::interpreter::gas::{WITNESS_BRANCH_READ, WITNESS_BRANCH_WRITE, WITNESS_CHUNK_FILL, WITNESS_CHUNK_READ, WITNESS_CHUNK_WRITE};
use ffi_interface::Context;
use revm_precompile::B256;
use verkle_spec::{Storage, Code, Hasher, U256 as VerkleU256, hash64};
const BASIC_DATA_LEAF_KEY: u8 = 0;
const CODE_HASH_LEAF_KEY: u8 = 1;
pub struct DefaultHasher;
impl Hasher for DefaultHasher {}
pub struct Witness<DB: VerkleDatabaseRef>{
    pub accessed_leaves: Vec<B256>,
    pub accessed_subtrees: Vec<Vec<u8>>,
    pub modified_leaves: Vec<B256>,
    pub modified_subtrees: Vec<Vec<u8>>,
    pub db: DB,
    // true part of this property is never used currently
    charge_fill_cost: bool,
}

impl<DB: VerkleDatabaseRef> Witness<DB> {
    // `charge_fill_cost` is false by default because currently we do not have any instance of charging for filling
    pub fn new(db: DB) -> Self {
        Self { accessed_leaves: vec![], accessed_subtrees: vec![vec![]], modified_leaves: vec![], modified_subtrees: vec![vec![]], charge_fill_cost: false, db }
    }

    pub fn accessed_leaves(&self) -> &Vec<B256> {
        &self.accessed_leaves
    }

    pub fn accessed_subtrees(&self) -> &Vec<Vec<u8>> {
        &self.accessed_subtrees
    }

    pub fn modified_leaves(&self) -> &Vec<B256> {
        &self.modified_leaves
    }

    pub fn modified_subtrees(&self) -> &Vec<Vec<u8>> {
        &self.modified_subtrees
    }

    pub fn access_account_data(&mut self, caller: Address, gas_available: &mut u64) -> Result<bool, DB::Error> {
        self.access_basic_data(alloy_addr20_to_addr32(caller), gas_available, false, true)
    }

    pub fn access_code_hash(
        &mut self,
        address: Address,
        gas_available: &mut u64,
    ) -> Result<bool, DB::Error> {
        let tree_index = [0u8; 32];

        self.access_account_subtree(
            alloy_addr20_to_addr32(address),
            tree_index,
            CODE_HASH_LEAF_KEY,
            gas_available,
            false,
            true,
        )
    }

    pub fn access_for_balance_op_code(&mut self, caller: Address, gas_available: &mut u64) -> Result<bool, DB::Error> {
        self.access_basic_data(alloy_addr20_to_addr32(caller), gas_available, false, true)
    }

    pub fn access_for_storage(&mut self, address: Address, key: VerkleU256, is_write: bool, gas_available: &mut u64) -> Result<bool, DB::Error> {
        let tree_key = Storage::new::<DefaultHasher>(alloy_addr20_to_addr32(address).into(), key).storage_slot();
        self.access_key(tree_key.to_fixed_bytes().into(), true, is_write, gas_available)
    }

    pub fn access_for_block_hash_op_code(&mut self, address: Address, key: VerkleU256, gas_available: &mut u64) -> Result<bool, DB::Error> {
        self.access_for_storage(address, key, false, gas_available)
    }

    pub fn access_for_code_program_counter(&mut self, address: Address, program_counter: u32, gas_available: &mut u64) -> Result<bool, DB::Error> {
        let chunk_id = calculate_code_chunk_id_from_pc(program_counter);
        self.access_code_chunk(address, chunk_id, false, gas_available)
    }

    pub fn access_and_charge_for_code_slice(&mut self, address: Address, start_included: u32, end_not_included: u32, is_write: bool, gas_available: &mut u64) -> Result<bool, DB::Error> {
        if start_included == end_not_included {
            return Ok(true);
        }

        let start_chunk_id = calculate_code_chunk_id_from_pc(start_included);
        let end_chunk_id = calculate_code_chunk_id_from_pc(end_not_included - 1);

        let mut ch = start_chunk_id;
        while ch <= end_chunk_id {
            if !self.access_code_chunk(address, ch, is_write, gas_available)? {
                return Ok(false);
            }
            ch = ch + VerkleU256::from(1u64);
        }

        Ok(true)
    }

    pub fn access_code_chunk(&mut self, address: Address, chunk_id: VerkleU256, is_write: bool, gas_available: &mut u64) -> Result<bool, DB::Error> {
        let key = Code::new::<DefaultHasher>(alloy_addr20_to_addr32(address).into(), chunk_id).code_chunk();
        self.access_key(key.to_fixed_bytes().into(), true, is_write, gas_available)
    }

    pub fn access_for_absent_account(&mut self, address: Address, gas_available: &mut u64) -> Result<bool, DB::Error> {
        self.access_complete_account(alloy_addr20_to_addr32(address).into(), gas_available, false, true)
    }

    pub fn access_for_self_destruct(
        &mut self,
        contract: Address,
        inheritor: Address,
        balance_is_zero: bool,
        inheritor_exist: bool,
        gas_available: &mut u64,
    ) -> Result<bool, DB::Error> {
        // Access basic data for the contract
        if !self.access_basic_data(alloy_addr20_to_addr32(contract), gas_available, false, true)? {
            return Ok(false);
        }

        // Skip if inheritor is precompile and balance is zero
        // NOTE: This method assumes precompile check is handled outside
        if balance_is_zero {
            return Ok(true); // Precompile check removed as it's handled outside
        }

        // Check if contract and inheritor are different
        let contract_not_same_as_beneficiary = contract != inheritor;
        if contract_not_same_as_beneficiary 
            && !self.access_basic_data(alloy_addr20_to_addr32(inheritor), gas_available, false, true)? {
            return Ok(false);
        }

        // Handle non-zero balance case
        if !balance_is_zero {
            if !self.access_basic_data(alloy_addr20_to_addr32(contract), gas_available, true, true)? {
                return Ok(false);
            }
            if !contract_not_same_as_beneficiary {
                return Ok(true);
            }

            if inheritor_exist {
                if !self.access_basic_data(alloy_addr20_to_addr32(inheritor), gas_available, true, true)? {
                    return Ok(false);
                }
            } else {
                if !self.access_complete_account(alloy_addr20_to_addr32(inheritor), gas_available, true, true)? {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    pub fn access_for_contract_creation_check(
        &mut self,
        contract_address: Address,
        gas_available: &mut u64,
    ) -> Result<bool, DB::Error> {
        self.access_complete_account(alloy_addr20_to_addr32(contract_address), gas_available, false, true)
    }

    pub fn access_for_contract_creation_init(
        &mut self,
        contract_address: Address,
        gas_available: &mut u64,
    ) -> Result<bool, DB::Error> {
        self.access_complete_account(alloy_addr20_to_addr32(contract_address), gas_available, true, true)
    }

    pub fn access_for_contract_created(
        &mut self,
        contract_address: Address,
        gas_available: &mut u64,
    ) -> Result<bool, DB::Error> {
        self.access_complete_account(alloy_addr20_to_addr32(contract_address), gas_available, true, true)
    }

    pub fn access_for_value_transfer(
        &mut self,
        from: Address,
        to: Address,
        gas_available: &mut u64,
    ) -> Result<bool, DB::Error> {
        Ok(self.access_basic_data(alloy_addr20_to_addr32(from), gas_available, true, true)?
            && self.access_basic_data(alloy_addr20_to_addr32(to), gas_available, true, true)?)
    }

    // remove the concept of `fake_gas` from all of the following methods

    pub fn access_for_gas_beneficiary(
        &mut self,
        gas_beneficiary: Address,
    ) -> Result<bool, DB::Error> {
        let mut fake_gas = 1_000_000;
        self.access_complete_account(alloy_addr20_to_addr32(gas_beneficiary), &mut fake_gas, false, false)
    }

    pub fn access_account_for_withdrawal(
        &mut self,
        address: Address,
    ) -> Result<bool, DB::Error> {
        let mut fake_gas = 1_000_000;
        self.access_complete_account(alloy_addr20_to_addr32(address), &mut fake_gas, false, false)
    }

    pub fn access_for_blockhash_insertion_witness(
        &mut self,
        address: Address,
        key: VerkleU256,
    ) -> Result<bool, DB::Error> {
        let mut fake_gas = 1_000_000;
        self.access_complete_account(alloy_addr20_to_addr32(address), &mut fake_gas, false, false)?;
        let tree_key = Storage::new::<DefaultHasher>(alloy_addr20_to_addr32(address).into(), key).storage_slot();
        self.access_key(tree_key.to_fixed_bytes().into(), false, true, &mut fake_gas)?;
        Ok(true)
    }

    pub fn access_for_transaction(
        &mut self,
        origin_address: Address,
        destination_address: Option<Address>,
        is_value_transfer: bool,
    ) -> Result<bool, DB::Error> {
        let mut fake_gas = 1_000_000;
        if !self.access_basic_data(alloy_addr20_to_addr32(origin_address), &mut fake_gas, true, false)? {
            return Ok(false);
        }
        if !self.access_code_hash_internal(alloy_addr20_to_addr32(origin_address), &mut fake_gas, false, false)? {
            return Ok(false);
        }

        if let Some(dest_addr) = destination_address {
            Ok(self.access_basic_data(alloy_addr20_to_addr32(dest_addr), &mut fake_gas, is_value_transfer, false)?
                && self.access_code_hash_internal(alloy_addr20_to_addr32(dest_addr), &mut fake_gas, false, false)?)
        } else {
            Ok(true)
        }
    }

    fn access_basic_data(
        &mut self,
        address: [u8; 32],
        gas_available: &mut u64,
        is_write: bool,
        charge_gas: bool,
    ) -> Result<bool, DB::Error> {
        let tree_index = [0u8; 32];

        self.access_account_subtree(
            address,
            tree_index,
            BASIC_DATA_LEAF_KEY,
            gas_available,
            is_write,
            charge_gas,
        )
    }

    fn access_code_hash_internal(
        &mut self,
        address: [u8; 32],
        gas_available: &mut u64,
        is_write: bool,
        charge_gas: bool,
    ) -> Result<bool, DB::Error> {
        self.access_account_subtree(address, [0u8; 32], CODE_HASH_LEAF_KEY, gas_available, is_write, charge_gas)
    }

    fn access_complete_account(&mut self, address: [u8; 32], gas_available: &mut u64, is_write: bool, charge_gas: bool) -> Result<bool, DB::Error> {
        Ok(self.access_basic_data(address, gas_available, is_write, charge_gas)?
            && self.access_code_hash_internal(address, gas_available, is_write, charge_gas)?)
    }

    fn access_account_subtree(
        &mut self,
        address: [u8; 32],
        tree_index: [u8; 32],
        sub_index: u8,
        gas_available: &mut u64,
        is_write: bool,
        charge_gas: bool,
    ) -> Result<bool, DB::Error> {
        let context = Context::default();
        let key = get_tree_key(&context, address, tree_index, sub_index);
        self.access_key(key.into(), charge_gas, is_write, gas_available)
    }

    fn access_key(
        &mut self,
        key: B256,
        charge_gas: bool,
        is_write: bool,
        gas_available: &mut u64,
    ) -> Result<bool, DB::Error> {
        let sub_tree_stem: Vec<u8> = key[..31].to_vec();
        let mut required_gas = 0;

        if charge_gas {
            let was_previously_not_accessed = !self.accessed_leaves.contains(&key);
            if was_previously_not_accessed {
                required_gas += WITNESS_CHUNK_READ;
                if !self.accessed_subtrees.contains(&sub_tree_stem) {
                    required_gas += WITNESS_BRANCH_READ;
                }
            }

            if is_write && (was_previously_not_accessed || !self.modified_leaves.contains(&key)) {
                required_gas += WITNESS_CHUNK_WRITE;
                if self.charge_fill_cost && self.db.get_leaf_ref(key.clone())?.is_none() {
                    required_gas += WITNESS_CHUNK_FILL;
                }
                if !self.modified_subtrees.contains(&sub_tree_stem) {
                    required_gas += WITNESS_BRANCH_WRITE;
                }
            }

            if required_gas > *gas_available {
                return Ok(false);
            }
            *gas_available -= required_gas;
        }

        self.accessed_leaves.push(key);
        self.accessed_subtrees.push(sub_tree_stem.clone());

        if is_write {
            self.modified_leaves.push(key);
            self.modified_subtrees.push(sub_tree_stem);
        }

        Ok(true)
    }
 
}

fn get_tree_key(context: &Context, address: [u8; 32], tree_index: [u8; 32], sub_index: u8) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&address);
    input[32..].copy_from_slice(&tree_index);
    let mut hash = hash64(&context.committer, input).to_fixed_bytes();
    hash[31] = sub_index;

    hash
}

// utility functions
fn alloy_addr20_to_addr32(address: Address) -> [u8; 32] {
    let bytes20: [u8; 20] = address.into();

    let mut bytes32: [u8; 32] = [0u8; 32];
    bytes32[12..].copy_from_slice(&bytes20);

    bytes32
}

fn calculate_code_chunk_id_from_pc(pc: u32) -> VerkleU256 {
    let chunk_id = pc / 31;
    VerkleU256::from(chunk_id)
}
