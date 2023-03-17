

use std::{borrow::Borrow, collections::HashMap};

use super::*;
use crate::{wallet::Wallet, subcommand::wallet::inscribe::Inscribe};
use bitcoincore_rpc::bitcoincore_rpc_json::CreateRawTransactionInput;
use rand::Rng; // 0.8.5use rand::Rng; // 0.8.5
use bitcoin::{SignedAmount, psbt::{PartiallySignedTransaction, serialize::Serialize}, hashes::hex::FromHex};
use glob::glob;

use {
  bitcoin::{
    blockdata::{opcodes, script},
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    secp256k1::{
      self,  rand, Secp256k1, XOnlyPublicKey,
    },
    util::sighash::{Prevouts, SighashCache},
    util::taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    PackedLockTime, SchnorrSighashType, Witness,
  },
  std::collections::BTreeSet,
};

const MAX_STANDARD_TX_WEIGHT: u64 = 400_000; // todo: compression fucks up all these tests that should fail @ 400k

#[derive(Debug, Parser)]
pub(crate) struct Transactions {
  #[clap(long, help = "Fetch at most <LIMIT> transactions.")]
  limit: Option<u16>,
  toglob: String,
  satoshis: i64,
  jares: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Output {
  pub transaction: Txid,
  pub confirmations: i32,
}


impl Transactions {
pub fn create_inscription_transactions(
  satpoint: Option<SatPoint>,
  inscription: Inscription,
  inscriptions: BTreeMap<SatPoint, InscriptionId>,
  network: Network,
  utxos: BTreeMap<OutPoint, Amount>,
  change: [Address; 2],
  destination: Address,
  commit_fee_rate: FeeRate,
  reveal_fee_rate: FeeRate,
  no_limit: bool,
) -> Result<(Transaction, Transaction, TweakedKeyPair, [u8;64])> {
  let satpoint = if let Some(satpoint) = satpoint {
    satpoint
  } else {
    let inscribed_utxos = inscriptions
      .keys()
      .map(|satpoint| satpoint.outpoint)
      .collect::<BTreeSet<OutPoint>>();

    utxos
      .keys()
      .find(|outpoint| !inscribed_utxos.contains(outpoint))
      .map(|outpoint| SatPoint {
        outpoint: *outpoint,
        offset: 0,
      })
      .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))?
  };

  for (inscribed_satpoint, inscription_id) in &inscriptions {
    if inscribed_satpoint == &satpoint {
      return Err(anyhow!("sat at {} already inscribed", satpoint));
    }

    if inscribed_satpoint.outpoint == satpoint.outpoint {
      return Err(anyhow!(
        "utxo {} already inscribed with inscription {inscription_id} on sat {inscribed_satpoint}",
        satpoint.outpoint,
      ));
    }
  }

  let secp256k1 = Secp256k1::new();
  let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
  let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

  let reveal_script = inscription.append_reveal_script(
    script::Builder::new()
      .push_slice(&public_key.serialize())
      .push_opcode(opcodes::all::OP_CHECKSIG),
  );

  let taproot_spend_info = TaprootBuilder::new()
    .add_leaf(0, reveal_script.clone())
    .expect("adding leaf should work")
    .finalize(&secp256k1, public_key)
    .expect("finalizing taproot builder should work");

  let control_block = taproot_spend_info
    .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
    .expect("should compute control block");

  let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

  let (_, reveal_fee) = Inscribe::build_reveal_transaction(
    &control_block,
    reveal_fee_rate,
    OutPoint::null(),
    TxOut {
      script_pubkey: destination.script_pubkey(),
      value: 0,
    },
    &reveal_script,
  );

  let unsigned_commit_tx = TransactionBuilder::build_transaction_with_value(
    satpoint,
    inscriptions,
    utxos,
    commit_tx_address.clone(),
    change,
    commit_fee_rate,
    reveal_fee + TransactionBuilder::TARGET_POSTAGE,
  )?;

  let (vout, output) = unsigned_commit_tx
    .output
    .iter()
    .enumerate()
    .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
    .expect("should find sat commit/inscription output");

  let (mut reveal_tx, fee) = Inscribe::build_reveal_transaction(
    &control_block,
    reveal_fee_rate,
    OutPoint {
      txid: unsigned_commit_tx.txid(),
      vout: vout.try_into().unwrap(),
    },
    TxOut {
      script_pubkey: destination.script_pubkey(),
      value: output.value,
    },
    &reveal_script,
  );

  reveal_tx.output[0].value = reveal_tx.output[0]
    .value
    .checked_sub(fee.to_sat())
    .context("commit transaction output value insufficient to pay transaction fee")?;

  if reveal_tx.output[0].value < reveal_tx.output[0].script_pubkey.dust_value().to_sat() {
    bail!("commit transaction output would be dust");
  }

  let mut sighash_cache = SighashCache::new(&mut reveal_tx);

  let signature_hash = sighash_cache
    .taproot_script_spend_signature_hash(
      0,
      &Prevouts::All(&[output]),
      TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
      SchnorrSighashType::Default,
    )
    .expect("signature hash should compute");

  let signature = secp256k1.sign_schnorr(
    &secp256k1::Message::from_slice(signature_hash.as_inner())
      .expect("should be cryptographically secure hash"),
    &key_pair,
  );

  let witness = sighash_cache
    .witness_mut(0)
    .expect("getting mutable witness reference should work");
  witness.push(signature.as_ref());
  witness.push(reveal_script);
  witness.push(&control_block.serialize());

  let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

  let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
  assert_eq!(
    Address::p2tr_tweaked(
      TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
      network,
    ),
    commit_tx_address
  );

  let reveal_weight = reveal_tx.weight();
  if !no_limit && reveal_weight > MAX_STANDARD_TX_WEIGHT.try_into().unwrap() {
    bail!(
      "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
    );
  }
  Ok((unsigned_commit_tx, reveal_tx, recovery_key_pair, *signature.as_ref()))
}
  pub(crate) fn run(mut self, options: Options) -> Result {
    
    let toptions = options.clone();
    let index = Index::open(&options)?;
    loop {
        index.update()?;
    
        let mut output = Vec::new();
        for tx in toptions
        .bitcoin_rpc_client_for_wallet_command(false)?
        .list_transactions(
            None,
            Some(self.limit.unwrap_or(u16::MAX).into()),
            None,
            None,
        )?
        {
            println!("{} {} ", tx.detail.amount, tx.info.confirmations);
            if tx.detail.amount.ge(&SignedAmount::from_sat(self.satoshis)) 
                && tx.info.confirmations > 0 {
                    println!("winner winner chickum dinner");
                    let mut dont = false;
                    let addy = tx.detail.address.as_ref().unwrap().to_string();
                    let num = rand::thread_rng().gen_range(0..6);
let sigh = self.jares.clone();
                       for j in sigh {
                           if j == tx.info.txid.to_string() {
                               dont = true;
                           }
                        }
                    println!("dont: {}", dont);
                    if dont == false { 
                        self.jares.push(tx.info.txid.to_string()    .clone());

                     
                        println!("dontfalse");
                        let boptions =options.clone();



                        println!("num: {}", num);

                        let mut files = glob("/home/ubuntu/Released/**/*.png")?;

                        let path = files.nth(num).unwrap().unwrap();
                        
                                    let file = path.display();
                                    let inscription = Inscription::from_file(boptions.chain(), file.to_string());

    let client = boptions.bitcoin_rpc_client_for_wallet_command(false)?;

    let mut utxos = index.get_unspent_outputs(Wallet::load(&boptions)?)?;

    let inscriptions = index.get_inscriptions(None)?;

    let commit_tx_change = [get_change_address(&client)?, get_change_address(&client)?];

    let reveal_tx_destination = tx.detail.address
      .map(Ok)
      .unwrap_or_else(|| get_change_address(&client))?;
    let (unsigned_commit_tx, reveal_tx, recovery_key_pair, witness) =
      Self::create_inscription_transactions(
        None,
        inscription.unwrap(),
        inscriptions,
        boptions.chain().network(),
        utxos.clone(),
        commit_tx_change,
        reveal_tx_destination,
        FeeRate::try_from(11.38).unwrap(),
        FeeRate::try_from(11.38).unwrap(),
        false
      )?;
    utxos.insert(
      reveal_tx.input[0].previous_output,
      Amount::from_sat(
        unsigned_commit_tx.output[reveal_tx.input[0].previous_output.vout as usize].value,
      ),
    );
    let fees =
    Inscribe::calculate_fee(&unsigned_commit_tx, &utxos) + Inscribe::calculate_fee(&reveal_tx, &utxos);

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
        .hex;

      let commit = client
        .send_raw_transaction(&signed_raw_commit_tx)
        .context("Failed to send commit transaction")?;

    // create an output tx for payment of self.satoshis

    let mut payment_tx = Transaction {
      version: 2,
      lock_time: PackedLockTime::ZERO,
      input: vec![TxIn {
        previous_output: OutPoint {
          txid: commit,
          vout: 0,
        },
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
        script_sig: Script::new(),
      }],
      output: vec![TxOut {
        value: self.satoshis as u64,
        script_pubkey: Address::from_str(&addy).unwrap().script_pubkey(),
      }],
    };
println!("1");use bitcoin::util::psbt::Input as PSBTInput;

let unsigned_reveal_tx = reveal_tx.clone();
let mut psbt = bitcoin::util::psbt::PartiallySignedTransaction {
    
   unsigned_tx: unsigned_reveal_tx,
   version : 0,
    xpub: BTreeMap::new(),
    proprietary : BTreeMap::new(),
    unknown: BTreeMap::new(),
    inputs: Vec::with_capacity(reveal_tx.input.len()),
    outputs: Vec::new(),
};
for input in reveal_tx.input.iter() {
  let witness = input.witness.clone();

  psbt.inputs.push(PSBTInput {
      non_witness_utxo: None,
      witness_utxo: Some(TxOut {
          value: 0, // Make sure to set the correct input value here
          script_pubkey: input.script_sig.clone(),
      }),
      final_script_sig: None,
      final_script_witness: Some(witness),
      bip32_derivation: BTreeMap::new(),
      partial_sigs: BTreeMap::new(),
      sighash_type: None,
      redeem_script: None,
      witness_script: None,
      ripemd160_preimages: BTreeMap::new(),
      sha256_preimages: BTreeMap::new(),
      hash160_preimages: BTreeMap::new(),
      hash256_preimages: BTreeMap::new(),
      tap_key_sig: None,
      tap_script_sigs: BTreeMap::new(),
      tap_scripts: BTreeMap::new(),
      tap_key_origins: BTreeMap::new(),
      tap_internal_key: None,
      tap_merkle_root: None,
      proprietary: BTreeMap::new(),
      unknown: BTreeMap::new(),
  });}


println!("2");
    //add payment_tx 
    let  payment_psbt = PartiallySignedTransaction::from_unsigned_tx(payment_tx.clone())?;
    psbt.combine(payment_psbt)?;
    
    let psbttx = psbt.extract_tx();

    // psbttx as base64
    let b64 = base64::encode(psbttx.serialize());
  
    print!("b64: {}", b64);

    /* 
taker: 
Input:
dummyUtxo
reveal
Payment

Output:
reveal
Ask
Change
 */

// add these inputs 
// dummyUtxo
//Payment
// add these outputs
//Ask
//Change

// finalize
// sign
// send


                        
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