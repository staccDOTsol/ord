use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    secp256k1::{
      self, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey,
    },
    util::key::PrivateKey,
    util::sighash::{Prevouts, SighashCache},
    util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    PackedLockTime,  Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
};
use axum::Json;
use base64::display::Base64Display;
use anyhow::Ok;
use bech32::encode;
use bitcoincore_rpc::bitcoincore_rpc_json::{CreateRawTransactionInput, SignRawTransactionInput};
use miniscript::{ToPublicKey};
use bitcoin::{util::{psbt::PartiallySignedTransaction, bip32::KeySource, sighash, bip143::SigHashCache, taproot::TaprootSpendInfo}, PublicKey,EcdsaSig, KeyPair, psbt::{Psbt, serialize::Serialize}, secp256k1::{ecdsa::{serialized_signature, SerializedSignature}, Message, schnorr, ffi::secp256k1_ecdsa_signature_serialize_der}, SchnorrSig, hashes::hex::FromHex, SchnorrSighashType};
use mp4::Bytes;
use serde::__private::de::Borrowed;
use serde_json::to_vec;
use std::{usize, collections::HashMap, io::{Read, BufWriter}, fs::OpenOptions};
use bitcoin::{hashes::hex::ToHex,   util::{taproot::TapSighashHash}};

use miniscript::{ psbt::PsbtExt};
use std::{io::{Write} , fs::File};

// rewriet imports to remove unused amd only keep the ones needed


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
  
      let (unsigned_commit_tx, mut reveal_tx
        , keypair, controlblock, reveal_script, taproot_spend_info ) =
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

      let output = Output {
        commit: unsigned_commit_tx.txid(),
        minter_fees,
        creator_fees
      };

      let output = serde_json::to_string_pretty(&output).unwrap();
      println!("{}", output);

      if self.dry_run {
        return Ok(());
      }
      
      let signed_commit_tx = client.sign_raw_transaction_with_wallet(
        
        &unsigned_commit_tx,
        None,
        None

      )?;

      let broadcasted_commit_tx = client.send_raw_transaction(&signed_commit_tx.hex)?;
      let broadcasted_commit_tx = broadcasted_commit_tx.to_string();
      println!("Broadcasted commit transaction: {}", broadcasted_commit_tx);
    
      let mut psbt =  PartiallySignedTransaction::from_unsigned_tx(reveal_tx.clone()).unwrap();
      // all the things up til now are just to get the psbt
      // now we need to add the witness and the signature
      // is revealtx signed already or not?
      // it is not signed
      // so we need to sign it with the keypair

      // whats' broken 
      // the signature is not being added to the psbt
      // the witness is not being added to the psbt
      // the psbt is not being finalized
      // the psbt is not being broadcasted
    
      let mut prevtxs = client.list_transactions(None, Some(1000), None, None ).unwrap()
      .iter()
      
      .filter(|tx| tx.info.txid == psbt.unsigned_tx.input[0].previous_output.txid)
      .map(|tx| client.get_raw_transaction (&tx.info.txid, None).unwrap())
      .collect::<Vec<Transaction>>();

let mut tx = psbt.unsigned_tx.clone();

let mut sighash_cache = SighashCache::new(  & mut  tx);
        let output = &unsigned_commit_tx.output[0].clone();

        let signature_hash = sighash_cache
          .taproot_script_spend_signature_hash( 
            0,
              &Prevouts::One(0, 
              output),
            TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
            SchnorrSighashType::SinglePlusAnyoneCanPay.into()
          )
          .expect("signature hash should compute");



        let secp256k1 = secp256k1::Secp256k1::new();
        // error: Invalid Schnorr signature size

          
        let dersig =  secp256k1.sign_schnorr(
          &Message::from_slice(&signature_hash[..]).unwrap(),
          &keypair 
          // noncedata?   

        ) ;
        
        // sighash type psuh it to the end of the signature before we serialize it
        // or after ?
        let mut signature = ( secp256k1::schnorr::Signature::to_hex(&dersig) ).as_bytes().to_vec();
       

        
        let mut ecdsasig = signature.clone();
        
        ecdsasig.push( SchnorrSighashType::SinglePlusAnyoneCanPay as u8 );
        let ecdsasig = ecdsasig.to_vec();



      // what if we don't add the final script sig?
      let mut input = psbt.inputs[0].clone();
      input.final_script_sig = Some(reveal_script.clone());
      psbt.inputs[0] = input.clone();
        

      let mut input = psbt.inputs[0].clone();
      let witness = sighash_cache
      .witness_mut(0)
      .expect("getting mutable witness reference should work");
      
      witness.push(signature.clone());
      witness.push(reveal_script.clone().into_bytes());
      witness.push(&controlblock.serialize() ); 

      input.final_script_witness = Some(  witness.clone() );
      psbt.inputs[0] = input.clone();



        let recovery_key_pair = keypair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());
        





        if !self.no_backup {
          Inscribe::backup_recovery_key(&client, recovery_key_pair,  Network::Bitcoin); 
        }

        // why is the signature not being added to the psbt?
        
              let signature = Base64Display::with_config(&signature.to_vec(), base64::STANDARD).to_string();
        
              println!("signature: {}", signature.clone() );
              println!("signature length: {}", signature.clone().len() );
              
              let mut input = psbt.inputs[0].clone();
        
let prevtxs = vec![SignRawTransactionInput {
        txid: unsigned_commit_tx.txid(),
        vout: 0,
        script_pub_key: unsigned_commit_tx.output[0].script_pubkey.clone(),
        amount: Some(Amount::from_sat(unsigned_commit_tx.output[0].value)),
        redeem_script: None,
        
      }];

      // what if we don't add the prevtxs?
      // then the psbt is not signed

      // what if we don't add the sighash type to the signature?
     
      // what if we don't add the witness?
      // then the psbt is not signed

      // what if we don't add the final script sig?
      // then the psbt is not signed

      psbt.inputs[0].witness_utxo = Some( TxOut {
        value: unsigned_commit_tx.output[0].value,
        script_pubkey: unsigned_commit_tx.output[0].script_pubkey.clone()
      });

      let mut input = psbt.inputs[0].clone();
      input.final_script_sig = Some(reveal_script.clone());
      psbt.inputs[0] = input.clone();

      let mut input = psbt.inputs[0].clone();
      input.final_script_witness = Some(  witness.clone() );
      psbt.inputs[0] = input.clone();

      let mut input = psbt.inputs[0].clone();
      input.sighash_type = Some(SchnorrSighashType::SinglePlusAnyoneCanPay.into());
      psbt.inputs[0] = input.clone();

      let mut input = psbt.inputs[0].clone();
      input.redeem_script = Some(reveal_script.clone());
      psbt.inputs[0] = input.clone();

      let mut input = psbt.inputs[0].clone();
      input.witness_script = Some(reveal_script.clone());
      psbt.inputs[0] = input.clone();

      let mut input = psbt.inputs[0].clone();
      input.bip32_derivation.insert(
        keypair.public_key() ,
       ( bitcoin::util::bip32::Fingerprint::default(),
        DerivationPath::default() )       );

      psbt.inputs[0] = input.clone();

      let hex = bitcoin::consensus::encode::serialize(&psbt);

      let prettyHex = hex::encode(&hex);
      println!("hex: {}", prettyHex);
      let psbt = Base64Display::with_config(&bitcoin::consensus::encode::serialize(&hex), base64::STANDARD) .to_string();
      println!("psbt b64: {}", psbt);

      
      
      let psbt: Psbt = bitcoin::consensus::encode::deserialize(&hex).unwrap(); // error: Invalid Taproot control block size
      //

      println!("psbt vsize {}", psbt.unsigned_tx.vsize());
      println!("psbt weight {}", psbt.unsigned_tx.get_weight());
      println!("psbt size {}", psbt.unsigned_tx.get_size());
      println!("psbt fee {}", Self::calculate_fee(&psbt.unsigned_tx, &utxos) );

      println!("psbt: {}", psbt.clone().extract_tx().txid() );
      println!("estimated fee: {}", Self::calculate_fee(&psbt.clone().extract_tx(), &utxos) );
      println!("estimated fees for commit and reveal: {} {} "
      , Self::calculate_fee(&unsigned_commit_tx, &utxos)
      , Self::calculate_fee(&reveal_tx, &utxos) );

      

      let psbt = Base64Display::with_config(&bitcoin::consensus::encode::serialize(&hex), base64::STANDARD) .to_string();

        // and now the client should be ready to update,
        // combine
        // finalize
        // and broadcast the transaction
        // step 1. update the psbt
        // step 2. combine the psbt
        // step 3. finalize the psbt
        // step 4. sign the psbt
        // step 5. broadcast the transaction
        
        // when I run this code, will the client be able to update the psbt?
        // yes
        // what if we don't add the sighash type to the signature?
        // then the psbt is not signed
        // what if we don't add the prevtxs?
        // then the psbt is not signed
        // what if we don't add the final script sig?
        // then the psbt is not signed
        // what if we don't add the final script witness?

      let mut file = OpenOptions::new()
      .write(true)
      .append(true)
      .open("psbthex.txt")
      .unwrap();
      file.write_all( prettyHex.as_bytes() )?;
      let mut file = OpenOptions::new()
      .write(true)
      .append(true)
      .open("psbtpsbt.txt")
      .unwrap();
      file.write_all( psbt.as_bytes() )?;
      // step 9. broadcast the transaction
      
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
let signed_psbt = client.wallet_process_psbt(&serialized_psbt, Some(true), Some(SchnorrSighashType::SinglePlusAnyoneCanPay.into()), None).unwrap().psbt;
        
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
  ) -> Result<( Transaction, Transaction, KeyPair, ControlBlock, Script, TaprootSpendInfo ), anyhow::Error> {
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
   

    // let reveal_tx = reveal_tx.clone();

    Ok((unsigned_commit_tx, reveal_tx
      ,  key_pair, control_block,reveal_script , taproot_spend_info))
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

    let mut reveal_tx = Transaction {
      input: vec![ TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      },
      TxIn {
        previous_output: input2,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }
      ],
      output: vec![output2,output],
      lock_time: PackedLockTime::ZERO,
      version: 1,
      // SINGLE AND ANYONECANPAY
    };



    (reveal_tx,   vec![vec![], vec![], vec![]], a_fee)
  }


}