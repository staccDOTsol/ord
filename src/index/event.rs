use super::*;
use serde::{Deserialize, Serialize};



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityPool {
    pub id: u64,
    pub asset1: Rune,
    pub asset2: Rune,
    pub balance1: u128,
    pub balance2: u128,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LiquidityPoolData {
    pub asset1: Rune,
    pub asset2: Rune,
    pub balance1: u128,
    pub balance2: u128,
}
impl PartialEq for LiquidityPoolData {
    fn eq(&self, other: &Self) -> bool {
        self.asset1 == other.asset1 && self.asset2 == other.asset2 && self.balance1 == other.balance1 && self.balance2 == other.balance2
    }
}
impl PartialEq for LiquidityPool {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id &&
        self.asset1 == other.asset1 &&
        self.asset2 == other.asset2 &&
        self.balance1 == other.balance1 &&
        self.balance2 == other.balance2
    }
}

impl Eq for LiquidityPool {}

impl Eq for LiquidityPoolData {}


#[derive(Debug, Clone, PartialEq)]
pub enum Event {
  InscriptionCreated {
    block_height: u32,
    charms: u16,
    inscription_id: InscriptionId,
    location: Option<SatPoint>,
    parent_inscription_ids: Vec<InscriptionId>,
    sequence_number: u32,
  },
  InscriptionTransferred {
    block_height: u32,
    inscription_id: InscriptionId,
    new_location: SatPoint,
    old_location: SatPoint,
    sequence_number: u32,
  },
  RuneBurned {
    amount: u128,
    block_height: u32,
    rune_id: RuneId,
    txid: Txid,
  },
  RuneEtched {
    block_height: u32,
    rune_id: RuneId,
    txid: Txid,
  },
  RuneMinted {
    amount: u128,
    block_height: u32,
    rune_id: RuneId,
    txid: Txid,
  },
  RuneTransferred {
    amount: u128,
    block_height: u32,
    outpoint: OutPoint,
    rune_id: RuneId,
    txid: Txid,
  },
  LpUpdated {
    block_height: u32,
    lp: LiquidityPoolData,
  }
}
