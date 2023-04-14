use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    SigHashType,
    blockdata::{opcodes, script},
    policy::MAX_STANDARD_TX_WEIGHT,
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
use anyhow::Ok;
use bech32::ToBase32;
use bitcoincore_rpc::bitcoincore_rpc_json::FinalizePsbtResult;
use futures::future::UnwrapOrElse;
use log::kv::ToValue;
use miniscript::ToPublicKey;
use base64::display::Base64Display;
use bitcoin::{AddressType::P2pkh, psbt::Input,psbt::{Output as PsbtOutput, serialize::Serialize}, util::{psbt::PartiallySignedTransaction, sighash, amount::serde, taproot::TaprootMerkleBranch, key}, PublicKey, secp256k1::{Parity, ecdsa::{self, SerializedSignature}, schnorr, SecretKey}, EcdsaSig, KeyPair, Sighash, SchnorrSig};
use ::serde::__private::de::Borrowed;
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use std::{ops::{Deref, DerefMut}, io::{BufReader, Read}, collections::HashMap, slice, borrow::{BorrowMut, Borrow}, sync::Arc, usize };
use bitcoin::{consensus::serialize, hashes::hex::ToHex, psbt::{PsbtSighashType, Psbt}, EcdsaSighashType, util::{taproot::TapSighashHash, bip143::SigHashCache}};

use lazy_static::__Deref;
use miniscript::{Segwitv0, psbt::PsbtExt};
use std::{io::{Write, BufWriter} , fs::File};
#[derive(Serialize)]
struct Output {
  commit: Txid,
  minter_fees: f64,
  creator_fees: f64
}

#[derive(Debug, Parser)]
pub(crate) struct Inscribe {
  #[clap(long, help = "Inscribe <SATPOINT>")]
  pub(crate) satpoint: Option<SatPoint>,
  #[clap(long, help = "Use fee rate of <FEE_RATE> sats/vB")]
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
}
// define a type for the output of the function

// define a type for the output of the function

impl Inscribe {

async fn write_file (psbt: PartiallySignedTransaction, tx: Transaction) {
  let mut file = OpenOptions::new().write(true).create(true).truncate(false).append(true).open("psbt.txt").await.unwrap();
  file.write_all(serde_json::to_string(&psbt).unwrap().as_bytes()).await.unwrap();
  let mut file = OpenOptions::new().write(true).create(true).truncate(false).append(true).open("tx.txt").await.unwrap(); 
  file.write_all(serde_json::to_string(&tx).unwrap().as_bytes()).await.unwrap();
}
  fn from_utxos<'a>(utxos: &'a BTreeMap<bitcoin::OutPoint, Amount>
  ,mut map: HashMap::<usize, (u32, Borrowed<'a, bitcoin::TxOut>)>, inputs:&'a  Vec<Input>, ) ->
  Result<(HashMap<usize, (u32, Borrowed<'a, bitcoin::TxOut>)>  )> {
       
      let mut utxos = utxos.clone();
      let mut utxos = utxos.clone();

      inputs.iter().enumerate().for_each(|(i, input)| {
        let prevout =input.non_witness_utxo.as_ref().unwrap();
        let TxOut = &input.witness_utxo.as_ref().borrow().unwrap()  ;
        let outpoint = OutPoint {
          txid: prevout.txid(),
          vout: prevout.input[i].previous_output.vout,
        };
        let amount = utxos.get(&outpoint).unwrap();
        map.insert(i, (amount.as_sat() as u32,  Borrowed(TxOut  )));
      });
      Ok(map)
  }
  pub(crate) fn run(self, options: Options) -> Result {
    let inscription = Inscription::from_file(options.chain(), &self.file)?;
    
    let index = Index::open(&options)?;
    index.update()?;

    let client = options.bitcoin_rpc_client_for_wallet_command(false)?;

    let mut utxos = index.get_unspent_outputs(Wallet::load(&options)?)?;
    
    utxos = utxos.iter_mut()
    .filter(|(_, amount )| amount.as_sat() > 1000 && amount.as_sat() < 66600) 
    .map(|(txid, amount)| (*txid, *amount))
      .collect();

    
   
      let inscriptions = index.get_inscriptions(None)?;

      let commit_tx_change = [get_change_address(&client)?, get_change_address(&client)?];
  
      let reveal_tx_destination = self
        .destination
        .map(Ok)
        .unwrap_or_else(|| get_change_address(&client))?;
  
      let (unsigned_commit_tx, reveal_tx, recovery_key_pair 
        , witness, tapsighash, keypair, controlblock, signature,  publickey  ) =
        Inscribe::create_inscription_transactions(
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
        )?;
  

        if !self.no_backup {
          Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
        }
      utxos.insert(
        reveal_tx.input[0].previous_output,
        Amount::from_sat(
          unsigned_commit_tx.output[reveal_tx.input[0].previous_output.vout as usize].value,
        ),
      );

    let creator_fees =
      Self::calculate_fee(&unsigned_commit_tx, &utxos);
      
      let minter_fees = Self::calculate_fee(&reveal_tx, &utxos);
      let asking_price = reveal_tx.output[0].value as f64;
      let total_fees = creator_fees + minter_fees;
      let total_price = asking_price + total_fees;
      let total_price = total_price / 100_000_000.0;
      let creator_fees = creator_fees / 100_000_000.0;
      let minter_fees = minter_fees / 100_000_000.0;
      let diff = total_price - creator_fees - minter_fees;
      let diff = diff / 100_000_000.0;

      let mut output = Output {
        commit: unsigned_commit_tx.txid(),
        minter_fees: minter_fees,
        creator_fees: creator_fees
      };

      println!("  Commit transaction: {}", unsigned_commit_tx.txid());
      println!("  Reveal transaction: {}", reveal_tx.txid());
      println!("  Tapsighash: {}", tapsighash);
      println!("  Signature: {}", signature);
      println!("  PublicKey: {}", publickey);
      println!("  Creator Fees: {}", creator_fees);
      println!("  Minter Fees: {}", minter_fees);
      println!("  Total Fees: {}", total_fees);
      println!("  Asking Price: {}", asking_price);
      println!("  Total Price: {}", total_price);
      println!("  Diff: {}", diff);



      println!("  Commit transaction: {}", serde_json::to_string(&unsigned_commit_tx).unwrap()  );        
      println!("  Reveal transaction: {}", serde_json::to_string(&reveal_tx).unwrap()  );
      
      let mut psbt = PartiallySignedTransaction::from_unsigned_tx(reveal_tx).unwrap();
let mut borrowed: HashMap::<usize, (u32, Borrowed<bitcoin::TxOut>)> = HashMap::new();
 let borrowed = Self::from_utxos(&utxos, borrowed, &psbt.inputs.clone()).unwrap(); 
              
                for i in 0..psbt.inputs.len() {


    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);

                  let secp256k1 = bitcoin::secp256k1::Secp256k1::new();
                  let previous_output = psbt.inputs[i].witness_utxo.as_ref().unwrap().clone();
                  let extracty = psbt.clone().extract_tx();
                  let mut sighash_cache = SighashCache::new(& extracty);
                  let public_key = bitcoin::PublicKey::from_str(&publickey.to_string()).unwrap();
                  let secp = bitcoin::secp256k1::Secp256k1::new();

let mut prevouts: HashMap::<usize, (u32, Borrowed<bitcoin::TxOut>)> = HashMap::new();
let prevouts = Self::from_utxos(&utxos, prevouts, &psbt.inputs.clone()).unwrap();
                  let outpoint = psbt.inputs[i].witness_utxo.as_ref().unwrap().clone().value  as usize;
                  let utxo = utxos.iter().nth(outpoint).unwrap();
                  let outpoint = {
                    let mut outpoint = bitcoin::OutPoint::default();
                    outpoint.txid = utxo.0.txid;
                    outpoint.vout = utxo.0.vout;
                    outpoint  
                   };

                   let previous_output = psbt.inputs[i].witness_utxo.as_ref().unwrap().clone();
                  let reveal_script = bitcoin::Script::from_str(
                    
                    serde_json::to_string(&witness).unwrap().as_str()
                  ).unwrap();

                  let keypair = bitcoin::util::key::PrivateKey::from_str
                  (
                 serde_json::to_string(&recovery_key_pair ).unwrap().as_str()
                ).unwrap();
                  let leaf_hash = bitcoin::hashes::sha256d::Hash::hash(&public_key.to_bytes());
                  
                let sighash = sighash_cache.taproot_script_spend_signature_hash(
                  i,
                   &Prevouts::One(i, &previous_output), 
                    TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript  ), SchnorrSighashType::SinglePlusAnyoneCanPay
                );
                
                
                let endcoded_sig = serde_json::to_string(&signature.to_hex());
                let endcoded_sig2 =  hex::decode(endcoded_sig.unwrap().as_str()).unwrap();
               // endcoded_sig = endcoded_sig2  ;
                let mut sig = vec![0u8; endcoded_sig2.len() + 1];
                sig[0] = SchnorrSighashType::SinglePlusAnyoneCanPay as u8;
                sig[1..].copy_from_slice(&endcoded_sig2 );
                psbt.inputs[i].partial_sigs.insert(public_key, EcdsaSig::from_slice(&endcoded_sig2 ).unwrap()  );
              }
              let tpsbt = psbt.clone();
              let tx = psbt.extract_tx();
              Self::write_file(tpsbt.clone(), tx.clone() );
              Ok(())
            }


   
  fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> f64 {
    let mut fee = 0.0;
    

    for input in &tx.input {
      fee += utxos.get(&input.previous_output).unwrap().as_sat() as f64;
    }
    for output in &tx.output {
      fee -= output.value as f64;
    fee = fee / 100000000.0;
    } 

    fee

  } 
  
    


  fn create_inscription_transactions (
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
  ) -> Result<(Transaction, Transaction, TweakedKeyPair, Witness, TapSighashHash, KeyPair, ControlBlock, Signature,  PublicKey)> {
    let satpoint = if let Some(satpoint) = satpoint {
      satpoint
    } else {
      let inscribed_utxos = inscriptions  .clone()
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
    println!("commit tx address: {}", commit_tx_address);
    let (_, _, reveal_fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint::null(),
      OutPoint::null(),
      TxOut {
        script_pubkey: destination.script_pubkey(),
        value: 0,
      },
      &reveal_script,
      Amount::ZERO,
    );

    let unsigned_commit_tx = TransactionBuilder::build_transaction_with_value(
      satpoint,
      inscriptions.clone(),
      utxos.clone(),
      commit_tx_address.clone(),
      change,
      commit_fee_rate,
      TransactionBuilder::TARGET_POSTAGE,
    )?;

    let (vout, output) = unsigned_commit_tx
      .output
      .iter()
      .enumerate()
      .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
      .expect("should find sat commit/inscription output");
    let inscribed_utxos = inscriptions.clone()
    .keys()
    .map(|satpoint| satpoint.outpoint)
    .collect::<BTreeSet<OutPoint>>();

      let dummy_utxo = utxos
        .keys()
        .find(|outpoint| !inscribed_utxos.contains(outpoint))
        
        .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))
        .unwrap();

    let ( mut reveal_tx,  witness, fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint {
        txid: unsigned_commit_tx.txid(),
        vout: vout.try_into().unwrap(),
      },
      *dummy_utxo ,
      TxOut {
        script_pubkey:  destination.script_pubkey(),
        value: output.value, // TODO: subtract modest portion of fee
        // good thing we alredy call reveal twice   
        // we shouold fix the guess fees function

      },
      &reveal_script,reveal_fee
    );
    println!("reveal tx fee: {}", fee);
    let mut sighash_cache = SighashCache::new(  & mut reveal_tx);
   
    let signature_hash = sighash_cache
      .taproot_script_spend_signature_hash(
        // idnex 1 is tha taproot garbage output
        1,
          &Prevouts::One(1,  
          output),
        TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
        SchnorrSighashType::SinglePlusAnyoneCanPay
      )
      .expect("signature hash should compute");

    // what do I sign aobuve ? which prevout? 


    let signature = secp256k1.sign_schnorr(
      &secp256k1::Message::from_slice(signature_hash.as_inner())
        .expect("should be cryptographically secure hash"),
      &key_pair,
    );
// the fo
let mut witness: Vec<Vec<u8>> = Vec::new();
witness.push(bitcoin::consensus::encode::serialize(&signature.to_hex()));
    witness.push(reveal_script.clone().into_bytes());
    witness.push(control_block.serialize());

    let witness = Witness::from_vec(witness);

    let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

    let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
    assert_eq!(
      Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
        network,
      ),
      commit_tx_address
    );


    // let reveal_tx = reveal_tx.clone();

    Ok((unsigned_commit_tx, reveal_tx
      , recovery_key_pair, witness.clone(), signature_hash, key_pair, control_block, signature, public_key.to_public_key()))
  }

  fn backup_recovery_key(
    client: &Client,
    recovery_key_pair: TweakedKeyPair,
    network: Network,
  ) -> Result {
    let recovery_private_key = PrivateKey::new(recovery_key_pair.to_inner().secret_key(), network);

    let info = client.get_descriptor_info(&format!("rawtr({})", recovery_private_key.to_wif()))?;

    let response = client.import_descriptors(ImportDescriptors {
      descriptor: format!("rawtr({})#{}", recovery_private_key.to_wif(), info.checksum),
      timestamp: Timestamp::Now,
      active: Some(false),
      range: None,
      next_index: None,
      internal: Some(false),
      label: Some("commit tx recovery key".to_string()),
    })?;

    for result in response {
      if !result.success {
        return Err(anyhow!("commit tx recovery key import failed"));
      }
    }

    Ok(())
  }



  fn build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    input: OutPoint,
    input2: OutPoint,
    output: TxOut,
    script: &Script,
    a_fee: Amount,
  ) -> (Transaction, Vec<Vec<u8>> , Amount) {
    
    
      // prepend an output with  an ask for 500 000 sats. SIGHASH SINGLE will ensure we get it !
      let mut output2 = TxOut::default();
      output2.value = 6666 + a_fee.as_sat();
      output2.script_pubkey = Address::from_str("bc1pzjhmz2egst0etq0r6050m32a585nzwmhxjx23txqdyrwr2p83dwqxzj908").unwrap().script_pubkey();
     // create a tx as previous output with a dummy input
   

    let reveal_tx = Transaction {
      input: vec![ TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }, TxIn {
        previous_output: input2,
        script_sig: Script::new(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        
      }],
      output: vec![ output, output2],
      lock_time: PackedLockTime::ZERO,
      version: 1,
      // SINGLE AND ANYONECANPAY
     
    };
    //println!("reveal tx: {}", reveal_tx);
    //println!("reveal tx: {}", reveal_tx);

    // make reveal tx sighash type SINGLE | ANYONECANPAY
    //let sighash_type = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY; 

    



    (reveal_tx,   vec![vec![], vec![], vec![]], a_fee)
  }


}