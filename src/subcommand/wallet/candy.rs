use super::*;

use bitcoin::SignedAmount;
use bitcoincore_rpc::bitcoincore_rpc_json::GetTransactionResultDetailCategory;
use glob::glob;


#[derive(Debug, Parser)]
pub(crate) struct Transactions {
  #[clap(long, help = "Fetch at most <LIMIT> transactions.")]
  limit: Option<u16>,
  toglob: String,
  satoshis: i64
}

#[derive(Serialize, Deserialize)]
pub struct Output {
  pub transaction: Txid,
  pub confirmations: i32,
}

impl Transactions {
  pub(crate) fn run(self, options: Options) -> Result {
    loop {
        let mut output = Vec::new();
        for tx in options
        .bitcoin_rpc_client_for_wallet_command(false)?
        .list_transactions(
            None,
            Some(self.limit.unwrap_or(u16::MAX).into()),
            None,
            None,
        )?
        {
            if tx.detail.amount.ge(&SignedAmount::from_sat(self.satoshis)) 
                && tx.detail.category == GetTransactionResultDetailCategory::Receive
                && tx.info.confirmations > 0 {
                    let mut dont = false;
                    let files = glob(&self.toglob.to_string()).unwrap();
                    let addy = tx.detail.address.as_ref().unwrap().to_string();
                    for f in files {
                        let file = f.unwrap();
                        let fstr = file.to_str().unwrap().to_string();
                       
                        if fstr.contains(&addy) {
                            dont = true;
                        }
                    }
                    if dont == false {
                        let files = glob(&self.toglob.to_string()).unwrap();
                        for f in files {
                            let file = f.unwrap();
                            let fstr = file.to_str().unwrap().to_string();
                            if fstr.contains("png") {
                            
                                std::fs::rename(fstr, self.toglob.to_string() + &addy.to_owned())?;
                                super::wallet::inscribe::Inscribe {
                                    fee_rate: FeeRate::try_from(1.0).unwrap(),
                                    commit_fee_rate: None,
                                    file: file,
                                    no_backup: true,
                                    satpoint: None,
                                    dry_run: false,
                                    no_limit: false,
                                    destination: Some(tx.detail.address.as_ref().unwrap().clone()),
                                }
                                    .run(options.clone())?; 
                                }
                            }
                        }
                }
            output.push(Output {
                transaction: tx.info.txid,
                confirmations: tx.info.confirmations,
            });
        }

        print_json(output)?;
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
  }
}
