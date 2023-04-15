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
use base64::display::Base64Display;
use anyhow::Ok;
use bech32::ToBase32;
use bitcoincore_rpc::bitcoincore_rpc_json::{FinalizePsbtResult, CreateRawTransactionInput, SignRawTransactionInput};
use futures::future::UnwrapOrElse;
use log::kv::ToValue;
use miniscript::{ToPublicKey, DescriptorPublicKey};
use bitcoin::{AddressType::P2pkh, psbt::Input,psbt::{Output as PsbtOutput, serialize::Serialize}, util::{psbt::PartiallySignedTransaction, sighash, amount::serde, taproot::TaprootMerkleBranch, key}, PublicKey, secp256k1::{Parity, ecdsa::{self, SerializedSignature}, schnorr, SecretKey}, EcdsaSig, KeyPair, Sighash, SchnorrSig, consensus::encode::serialize_hex};
use ::serde::__private::de::Borrowed;
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
        , witness, signature_hash, keypair, controlblock, signature,  publickey  ) =
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
      println!("  Tapsighash: {}", signature_hash);
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

      // sign the commit transaction
      
      let signed_commit_tx = client.sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?;
      let signed_commit_tx = signed_commit_tx.hex;

    
      let mut psbt = PartiallySignedTransaction::from_unsigned_tx(reveal_tx.clone()).unwrap();
      let signed_reveal_tx = client.sign_raw_transaction_with_wallet(&reveal_tx, None, None)?;

      let signed_reveal_tx:Transaction = bitcoin::consensus::encode::deserialize(&signed_reveal_tx.hex).unwrap();
      
      // extract signatures from the reveal transaction

      let mut signatures = Vec::new();
      let mut public_keys = Vec::new();
      let mut redeem_scripts = Vec::new();
      let mut witness_scripts = Vec::new();
      let mut unknowns = Vec::new();
      let mut sighash_types = Vec::new();
      
      for i in 0..signed_reveal_tx.input.len() {
        let input = &signed_reveal_tx.input[i]; 
        let witness = &input.witness.to_vec();
        let mut sig = Vec::new();
        let mut pub_key = Vec::new();
        let mut redeem_script = Vec::new();
        let mut witness_script = Vec::new();
        let mut unknown = Vec::new();
        let mut sighash_type = Vec::new();
        for j in 0..witness.len() {
          let item = &witness[j];
          if j == 0 {
            sig = item.to_vec(); // signature of type bitcoin::util::bip143::SighashComponents
          } else if j == 1 {
            pub_key = item.to_vec();
          } else if j == 2 {
            redeem_script = item.to_vec();
          } else if j == 3 {
            witness_script = item.to_vec();
          } else if j == 4 {
            unknown = item.to_vec();
          } else if j == 5 {
            sighash_type = item.to_vec();
          }
        }
        signatures.push(  bitcoin::consensus::encode::serialize(&sig) );
        public_keys.push(pub_key);
        redeem_scripts.push(redeem_script);
        witness_scripts.push(witness_script);
        unknowns.push(unknown);
        sighash_types.push(sighash_type);
      }

      // add the signatures to the psbt

      for i in 0..psbt.clone().inputs.len() {
        let (public_key, redeem_script, witness_script, sighash_type) = (
          public_keys[i].clone(),
          redeem_scripts[i].clone(),
          witness_scripts[i].clone(),
          sighash_types[i].clone(),
        );
        let mut input = psbt.clone().inputs[i].clone();
        let single_plus_anyone = 0x81;
        let leaf_hash = bitcoin::hashes::sha256d::Hash::hash(serde_json::to_string(&public_key ).unwrap().as_str().as_bytes());
        
        
        let sighash = signature_hash;
        let sighash_message = secp256k1::Message::from_slice(&sighash).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret_key = keypair.secret_key() ;
        let signature = secp.sign_ecdsa(&sighash_message, &secret_key );
        let endcoded_sig = signature.serialize_der();
        
        let mut sig = [0u8; 65];
        sig[0] = single_plus_anyone;
        sig[1..].copy_from_slice(&endcoded_sig );
        let mut sig = signatures[i].clone();
        let mut pub_key = bitcoin::consensus::encode::serialize(&public_key);
        let mut redeem_script: Script = bitcoin::consensus::encode::deserialize(&redeem_script).unwrap();
        let mut witness_script : Script= bitcoin::consensus::encode::deserialize(&witness_script).unwrap()  ;
        let mut unknown: Vec<u8>  = Vec::new();
        if sig.len() > 0 {
          
          input.partial_sigs.insert(
            bitcoin::PublicKey::from_str(
            serde_json::to_string(&public_key ) .unwrap().as_str() ).unwrap(),
            EcdsaSig::from_slice(&sig).unwrap()  );
        }
        if pub_key.len() > 0 {
          input.final_script_sig = Some(Script::new());
        }

        

        if redeem_script.len() > 0 {
          input.redeem_script = Some(redeem_script);
        }
        if witness_script.len() > 0 {
          input.witness_script = Some(witness_script);
        }
        if unknown.len() > 0 { // this is always true 
          input.unknown.insert(bitcoin::psbt::raw::Key { type_value: 0, key: unknown.clone() }, unknown.clone());
        }

        psbt.inputs[i] = input;
        psbt.clone().finalize_inp(&secp, i).unwrap();

        
      } 
      // anythign else to do here ?
      // psbt.finalize_all() ?


      // sign the psbt
      // but it's already signed ? 
      let signed_psbt = client.wallet_process_psbt(&Base64Display::with_config(
        &bitcoin::consensus::encode::serialize(&psbt)
        , base64::STANDARD).to_string(), None, Some(SigHashType::SinglePlusAnyoneCanPay.into()),None ).unwrap().psbt;  


println!("  Signed PSBT: {}", signed_psbt);
// provided a redeem script for a transaction output that does not need one 
// let broadcasted_reveal_tx = client.send_raw_transaction(&signed_psbt)?;


let mut file = File::create("signed_psbt.txt")?;
file.write_all( signed_psbt .as_bytes())?;

let broadcasted_commit_tx = client.send_raw_transaction(&signed_commit_tx)?;




// let broadcasted_reveal_tx = client.send_raw_transaction(&signed_psbt)?;
Ok(())
}
/*

 for i in 0..psbt.inputs.len() {
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    
    // there is not witnesutxo in the psbt
    if psbt.inputs[i].witness_utxo.is_none() {
      continue;
    }
   let previous_output = psbt.inputs[i].witness_utxo.as_ref().unwrap().clone();
    let reveal_script = bitcoin::Script::from_str(
      serde_json::to_string(&witness).unwrap().as_str()
    ).unwrap();
    let keypair = bitcoin::util::key::PrivateKey::from_str  (
      serde_json::to_string(&recovery_key_pair ).unwrap().as_str()
    ).unwrap();
    let leaf_hash = bitcoin::hashes::sha256d::Hash::hash(serde_json::to_string(&public_key ).unwrap().as_str().as_bytes());
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
      i,
      &Prevouts::One(i, previous_output), //&Prevouts::One(i, &previous_output
      TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript  ),
      SchnorrSighashType::SinglePlusAnyoneCanPay
    ).unwrap()  ;
    let sighash_message = secp256k1::Message::from_slice(&sighash).unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&keypair.to_bytes()).unwrap();
    let signature = secp.sign_ecdsa(&sighash_message, &secret_key );
    let endcoded_sig = serde_json::to_string(&signature);
    let endcoded_sig2 =  hex::decode(endcoded_sig.unwrap().as_str()).unwrap();
    let mut sig = vec![0u8; endcoded_sig2.len() + 1];
    sig[0] = SchnorrSighashType::SinglePlusAnyoneCanPay as u8;
    sig[1..].copy_from_slice(&endcoded_sig2 );
    psbt.inputs[i].partial_sigs.insert(
      bitcoin::PublicKey::from_str(
      serde_json::to_string(&public_key ) .unwrap().as_str() ).unwrap(),
      EcdsaSig::from_slice(&endcoded_sig2 ).unwrap()  );
  } 

          let serialized_psbt = base64::encode(serde_json::to_string(&psbt).unwrap());
let signed_psbt = client.wallet_process_psbt(&serialized_psbt, Some(true), Some(SigHashType::SinglePlusAnyoneCanPay.into()), None).unwrap().psbt;
        
        let psbt: PartiallySignedTransaction = serde_json::from_str(&signed_psbt).unwrap();
          let tpsbt = psbt.clone();
          let tx = psbt.extract_tx();
          Self::write_file(tpsbt.clone(), tx.clone() );
          Ok(())

        }
 */
   
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
      output: vec![output2, output],
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