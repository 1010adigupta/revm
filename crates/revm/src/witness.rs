use crate::primitives::{db::VerkleDatabaseRef, Address, U256};
use crate::interpreter::gas::{WITNESS_BRANCH_READ, WITNESS_BRANCH_WRITE, WITNESS_CHUNK_FILL, WITNESS_CHUNK_READ, WITNESS_CHUNK_WRITE};
use ffi_interface::{get_tree_key, Context};
use verkle_spec::{Storage, Code, Hasher, U256 as VerkleU256, H256};
const BASIC_DATA_LEAF_KEY: u8 = 0;
const CODE_HASH_LEAF_KEY: u8 = 1;
pub struct DefaultHasher;
impl Hasher for DefaultHasher {}
pub struct Witness<DB: VerkleDatabaseRef>{
    pub accessed_leaves: Vec<[u8; 32]>,
    pub accessed_subtrees: Vec<Vec<u8>>,
    pub modified_leaves: Vec<[u8; 32]>,
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

    pub fn accessed_leaves(&self) -> &Vec<[u8; 32]> {
        &self.accessed_leaves
    }

    pub fn accessed_subtrees(&self) -> &Vec<Vec<u8>> {
        &self.accessed_subtrees
    }

    pub fn modified_leaves(&self) -> &Vec<[u8; 32]> {
        &self.modified_leaves
    }

    pub fn modified_subtrees(&self) -> &Vec<Vec<u8>> {
        &self.modified_subtrees
    }

    pub fn access_account_data(&mut self, caller: [u8; 32], gas_available: &mut u64, is_write: bool, charge_gas: bool) -> Result<bool, DB::Error> {
        self.access_basic_data(caller, gas_available, is_write, charge_gas)
    }

    pub fn access_code_hash(
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
            CODE_HASH_LEAF_KEY,
            gas_available,
            is_write,
            charge_gas,
        )
    }

    pub fn access_for_balance_op_code(&mut self, caller: [u8; 32], gas_available: &mut u64, is_write: bool, charge_gas: bool) -> Result<bool, DB::Error> {
        self.access_basic_data(caller, gas_available, is_write, charge_gas)
    }

    pub fn access_for_storage(&mut self, address: H256, key: VerkleU256, is_write: bool, gas_available: &mut u64) -> Result<bool, DB::Error> {
        let tree_key = Storage::new::<DefaultHasher>(address, key).storage_slot();
        self.access_key(tree_key.into(), true, is_write, gas_available)
    }

    pub fn access_for_block_hash_op_code(&mut self, address: H256, key: VerkleU256, gas_available: &mut u64) -> Result<bool, DB::Error> {
        self.access_for_storage(address, key, false, gas_available)
    }

    pub fn access_for_code_program_counter(&mut self, address: H256, program_counter: u32, gas_available: &mut u64) -> Result<bool, DB::Error> {
        let chunk_id = Self::calculate_code_chunk_id_from_pc(program_counter);
        self.access_code_chunk(address, chunk_id, false, gas_available)
    }

    pub fn access_and_charge_for_code_slice(&mut self, address: H256, start_included: u32, end_not_included: u32, is_write: bool, gas_available: &mut u64) -> Result<bool, DB::Error> {
        if start_included == end_not_included {
            return Ok(true);
        }

        let start_chunk_id = Self::calculate_code_chunk_id_from_pc(start_included);
        let end_chunk_id = Self::calculate_code_chunk_id_from_pc(end_not_included - 1);

        let mut ch = start_chunk_id;
        while ch <= end_chunk_id {
            if !self.access_code_chunk(address, ch, is_write, gas_available)? {
                return Ok(false);
            }
            ch = ch + VerkleU256::from(1u64);
        }

        Ok(true)
    }

    pub fn access_code_chunk(&mut self, address: H256, chunk_id: VerkleU256, is_write: bool, gas_available: &mut u64) -> Result<bool, DB::Error> {
        let key = Code::new::<DefaultHasher>(address, chunk_id).code_chunk();
        self.access_key(key.into(), true, is_write, gas_available)
    }

    pub fn access_for_absent_account(&mut self, address: [u8; 32], gas_available: &mut u64) -> Result<bool, DB::Error> {
        self.access_complete_account(address, gas_available, false)
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
        self.access_key(key, charge_gas, is_write, gas_available)
    }

    fn access_key(
        &mut self,
        key: [u8; 32],
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

    fn access_complete_account(&mut self, address: [u8; 32], gas_available: &mut u64, is_write: bool) -> Result<bool, DB::Error> {
        let result = self.access_basic_data(address, gas_available, is_write, true)?
            && self.access_code_hash(address, gas_available, is_write, true)?;
        Ok(result)
    }

    fn calculate_code_chunk_id_from_pc(pc: u32) -> VerkleU256 {
        let chunk_id = pc / 31;
        VerkleU256::from(chunk_id)
    }
}

fn get_tree_key(context: &Context, address: Address, tree_index: [u8; 32], sub_index: u8) -> [u8; 32] {
    let context = Context::default();
    let key = get_tree_key(&context, address, tree_index, sub_index);
    key
}
