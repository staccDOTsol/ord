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
pub enum LiquidityOperation {
    AddLiquidity { rune_id: Rune, amount_1: u128, amount_2: u128 },
    RemoveLiquidity { rune_id: Rune, amount_1: u128, amount_2: u128 }
  }
impl LiquidityOperation {   
    pub fn encode(&self, payload: &mut Vec<u8>) {
        match self {
            LiquidityOperation::AddLiquidity { rune_id, amount_1, amount_2 } => {
                payload.push(128); // Arbitrary operation code for AddLiquidity
                payload.extend_from_slice(&rune_id.as_u128().to_le_bytes());
                payload.extend_from_slice(&amount_1.to_le_bytes());
                payload.extend_from_slice(&amount_2.to_le_bytes());
            },
            LiquidityOperation::RemoveLiquidity { rune_id, amount_1, amount_2 } => {
                payload.push(129); // Arbitrary operation code for RemoveLiquidity
                payload.extend_from_slice(&rune_id.as_u128().to_le_bytes());
                payload.extend_from_slice(&amount_1.to_le_bytes());
                payload.extend_from_slice(&amount_2.to_le_bytes());
            }
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LiquidityPoolData {
    pub id: u64,
    pub asset1: Rune,
    pub asset2: Rune,
    pub balance1: u128,
    pub balance2: u128,
    pub operation: Option<LiquidityOperation>
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



