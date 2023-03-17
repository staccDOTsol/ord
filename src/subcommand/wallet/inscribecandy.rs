
use std::io::Write;

use super::inscribe::Inscribe;

use glob::glob;
use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    secp256k1::{
      self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey,
    },
    util::key::PrivateKey,
    util::sighash::{Prevouts, SighashCache},
    util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    PackedLockTime, SchnorrSighashType, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
};

const MAX_STANDARD_TX_WEIGHT: u64 = 400_000; // todo: compression fucks up all these tests that should fail @ 400k

#[derive(Serialize)]
struct Output {
  commit: Txid,
  fees: u64,
}

  #[derive(Debug, Parser)]
  pub(crate) struct InscribeCandy {
    #[clap(long, help = "Inscribe <SATPOINT>")]
    pub(crate) satpoint: Option<SatPoint>,
    #[clap(
      long,
      default_value = "1.0",
      help = "Use fee rate of <FEE_RATE> sats/vB"
    )]
    pub(crate) fee_rate: FeeRate,
    #[clap(
      long,
      help = "Use <COMMIT_FEE_RATE> sats/vbyte for commit transaction.\nDefaults to <FEE_RATE> if unset."
    )]
    pub(crate) commit_fee_rate: Option<FeeRate>,
    #[clap(help = "Inscribe sat with contents of <FILE>")]
    pub(crate) file: PathBuf,
    #[clap(long, help = "Do not back up recovery key.")]
    pub(crate) no_backup: bool,
    #[clap(
      long,
      help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bitcoind in its default configuration. Do not use this flag unless you understand the implications."
    )]
    pub(crate) no_limit: bool,
    #[clap(long, help = "Don't sign or broadcast transactions.")]
    pub(crate) dry_run: bool,
    #[clap(long, help = "Send inscription to <DESTINATION>.")]
    pub(crate) destination: Option<Address>,
    pub(crate) candy_treasury: Option<Address>,
    pub(crate) candy_price: Option<i64>,
    pub(crate) toglob: String
  }
  
  impl InscribeCandy {
    pub(crate) fn run(self, options: Options) -> Result {
      let len : usize ;
        let files = glob(&self.toglob).unwrap();
        let commits = Vec::new();
                        for f in files {
                            let file = f.unwrap();
                            let fstr = file.to_str().unwrap().to_string();
                            if fstr.contains("png") {
                            
      let inscription = Inscription::from_file(options.chain(), &self.file)?;
  
      let index = Index::open(&options)?;
      index.update()?;
  
      let client = options.bitcoin_rpc_client_for_wallet_command(false)?;
  
      let mut utxos = index.get_unspent_outputs(Wallet::load(&options)?)?;
  
      let inscriptions = index.get_inscriptions(None)?;
      len = inscriptions.len();
      let commit_tx_change = [get_change_address(&client)?, get_change_address(&client)?];
  
      let reveal_tx_destination = self
        .destination
        .map(Ok)
        .unwrap_or_else(|| get_change_address(&client))?;
      let (unsigned_commit_tx) =
        Inscribe::create_candy_inscription_transactions(
          self.satpoint,
          inscription,
          inscriptions,
          options.chain().network(),
          utxos.clone(),
          commit_tx_change,
          reveal_tx_destination,
          self.commit_fee_rate.unwrap_or(self.fee_rate),
          self.fee_rate,
          self.no_limit,
          options.candy_treasury,
          options.candy_price,
        )?;
  
      let fees =
        Inscribe::calculate_fee(&unsigned_commit_tx, &utxos);
  
    
  
        let signed_raw_commit_tx = client
          .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
          .hex;
  
        let commit = client
          .send_raw_transaction(&signed_raw_commit_tx)
          .context("Failed to send commit transaction")?;
  
  
        print_json(Output {
          commit,
          fees,
        })?;
        commits.push(commit);
      };
    }
File::create("temp.txt").unwrap();
    let mut file = File::open("temp.txt").unwrap();
    for commit in commits {
      file.write_all(commit.to_string().as_bytes()).unwrap();
    }
    file.write_all(len.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();

    super::wallet::inscribe::Inscribe {
      fee_rate: FeeRate::try_from(1.0).unwrap(),
      commit_fee_rate: None,
      file: "temp.txt".into(),
       no_backup: true,
      satpoint: None,
      dry_run: false,
      no_limit: false,
      destination: Some(self.candy_treasury.as_ref().unwrap().clone()),
      candy_treasury: None,
      candy_price: None,
  }.run(options).unwrap();
      Ok(())
    }
}