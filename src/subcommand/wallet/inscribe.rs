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
    PackedLockTime, SchnorrSighashType, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
};
use base64::display::Base64Display;
use anyhow::Ok;
use bitcoincore_rpc::bitcoincore_rpc_json::{CreateRawTransactionInput, SignRawTransactionInput};
use miniscript::{ToPublicKey};
use bitcoin::{util::{psbt::PartiallySignedTransaction, bip32::KeySource}, PublicKey,EcdsaSig, KeyPair, psbt::{Psbt, PsbtSighashType, serialize::Serialize}, secp256k1::ecdsa::{serialized_signature, SerializedSignature}, SchnorrSig};
use mp4::Bytes;
use serde_json::to_vec;
use std::{usize, collections::HashMap, io::Read};
use bitcoin::{hashes::hex::ToHex,  EcdsaSighashType as SigHashType, util::{taproot::TapSighashHash}};

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
    
      let mut psbt = Psbt::from_unsigned_tx(reveal_tx.clone()).unwrap();
      // all the things up til now are just to get the psbt
      // now we need to add the witness and the signature
      // is revealtx signed already or not?
      // it is not signed
      // so we need to sign it with the keypair
      let mut prevtxs: Vec<SignRawTransactionInput> = Vec::new();
       let prevtx = SignRawTransactionInput {
         txid: unsigned_commit_tx.txid(),
         script_pub_key: unsigned_commit_tx.output[0].script_pubkey.clone(),
       vout: 0,
         redeem_script: None,
         amount: Some(Amount::from_sat(unsigned_commit_tx.output[0].value)),
       };
      prevtxs.push(prevtx);


      let signed_reval_tx = client.sign_raw_transaction_with_key(
        &reveal_tx,
       &[PrivateKey::new(keypair.secret_key(), Network::Bitcoin)],
        Some(prevtxs.to_vec().as_slice()),
        Some(SigHashType::SinglePlusAnyoneCanPay.into())
      ).unwrap();
      let signed_reval_tx = signed_reval_tx.hex;


      let signed_reval_tx: Transaction = bitcoin::consensus::encode::deserialize(&signed_reval_tx).unwrap();
      // won't work because the witness is not added
      // let signed_reval_tx = client.sign_raw_transaction_with_wallet(
      //   &reveal_tx,
      //   None,
      //   None
      // ).unwrap();
      // do we sign the reveal tx with the keypair or with the wallet?
      // we sign it with the keypair
      // so we need to get the keypair
      // we have the keypair
      // we need to get the witness
      // we have the witness
      // we need to get the signature
      // we have the signature
      // we need to get the publickey
      // we have the publickey
      // we need to get the controlblock
      // we have the controlblock
      // we need to get the signature hash
      // we have the signature hash
      // we need to get the prevtxs
      // we have the prevtxs
      // we need to get the psbt
      // we have the psbt
      
      let mut psbt = Psbt::from_unsigned_tx(reveal_tx.clone()).unwrap();

      let mut input = signed_reval_tx.input[0].clone();
      input.witness = witness.clone();

      let mut input = psbt.inputs[0].clone();
      input.witness_utxo = Some(TxOut {
        script_pubkey: unsigned_commit_tx.output[0].script_pubkey.clone(),
        value: (unsigned_commit_tx.output[0].value),
      });

      let mut input = psbt.inputs[0].clone();
      input.non_witness_utxo = Some(unsigned_commit_tx.clone());

      let mut input = psbt.inputs[0].clone();
      input.final_script_sig = Some(Script::new());

      let mut input = psbt.inputs[0].clone();
      input.final_script_witness = Some(witness.clone());
      let partial_sig = bitcoin::consensus::encode::serialize(&signature.to_hex());
      let partial_sig : EcdsaSig = EcdsaSig::from_slice(&partial_sig).unwrap();
      
      let mut input = psbt.inputs[0].clone();
      input.partial_sigs.insert(publickey, partial_sig);
      
      let mut input = psbt.inputs[0].clone();
      input.sighash_type = Some(SigHashType::SinglePlusAnyoneCanPay.into());
      let secppubkey = secp256k1::PublicKey::from_slice(&publickey.to_bytes()).unwrap();
      let keysource = KeySource::from((
        Fingerprint::from_str("00000000").unwrap(),
        DerivationPath::from_str("m/0").unwrap() )
      );
    input.bip32_derivation.insert(secppubkey, keysource); 

      let mut input = psbt.inputs[0].clone();


      
      // what if we don't add the witness script?
      let witness_script = bitcoin::Address::p2wsh(&Script::from(witness.serialize()), bitcoin::Network::Bitcoin).script_pubkey();
      input.witness_script = Some(witness_script.clone());
      let witness_script = bitcoin::consensus::encode::serialize(&witness_script);
      let witness_script = Base64Display::with_config(&witness_script, base64::STANDARD).to_string();
      
      let mut input = psbt.inputs[0].clone();
      // what if we don't add the redeem script?
      let redeem_script = bitcoin::Address::p2shwpkh(&publickey, bitcoin::Network::Bitcoin).unwrap().script_pubkey();
      input.redeem_script = Some(redeem_script.clone());
      let redeem_script = bitcoin::consensus::encode::serialize(&redeem_script);
      let redeem_script = Base64Display::with_config(&redeem_script, base64::STANDARD).to_string();
      
      // what if we don't add the sighash type?
      input.sighash_type = Some(SigHashType::SinglePlusAnyoneCanPay.into());
      // what if we don't add the partial signature?
      let partial_sig = bitcoin::consensus::encode::serialize(&signature.to_hex());
      let partial_sig : EcdsaSig = EcdsaSig::from_slice(&partial_sig).unwrap();
      
      input.partial_sigs.insert(publickey, partial_sig);
      
      let partial_sig = Base64Display::with_config(&partial_sig.to_vec(), base64::STANDARD).to_string();
      
      // what if we don't add the final script sig?
      let final_script_sig = bitcoin::consensus::encode::serialize(&serde_json::to_vec(&controlblock).unwrap());
      input.final_script_sig = Some(Script::from(final_script_sig.clone()));
      let final_script_sig = Base64Display::with_config(&final_script_sig, base64::STANDARD).to_string();
      
      println!("witness script: {}", witness_script);
      println!("redeem script: {}", redeem_script);
      println!("partial sig: {}", partial_sig);
      println!("final script sig: {}", final_script_sig);

      psbt.inputs[0] = input;

      // step 7 - sign the psbt
      // we need to get the psbt
      // we have the psbt
      // we need to get the keypair
      // we have the keypair
      // we need to get the prevtxs
      // we have the prevtxs
      // we need to get the sighash
      // we have the sighash
      // we need to get the signature
      // we have the signature
      // we need to get the publickey


    
      let psbt = Base64Display::with_config(&bitcoin::consensus::encode::serialize(&psbt), base64::STANDARD) .to_string();
    
      
    
    
    
      let signed_psbt = client.wallet_process_psbt(&psbt, Some(true), Some(SigHashType::SinglePlusAnyoneCanPay.into()), None).unwrap(); 
      let success = signed_psbt.complete;
      println!("success: {}", success);
      // step 8 - save the psbt to a file

      println!("psbt: {}", psbt);


      let mut file = File::create("psbt.txt")?;
      file.write_all( psbt .as_bytes() )?;
      // step 9. broadcast the transaction

      // why insist on a psbt?
      // we are creating a candy machine 
      // we need to be able to have people mint these inscriptionss at a later point in time
      
      
      
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
        0,
          &Prevouts::One(0, 
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
      }
      ],
      output: vec![ output],
      lock_time: PackedLockTime::ZERO,
      version: 1,
      // SINGLE AND ANYONECANPAY
     
    };
    // let reveal_tx = Transaction {
    //   input: vec![ TxIn {
    //     previous_output: input,
    //     script_sig: script::Builder::new().into_script(),
    //     witness: Witness::new(),
    //     sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    //   }],
    //   output: vec![output],
    //   lock_time: PackedLockTime::ZERO,
    //   version: 1,
    //   // SINGLE AND ANYONECANPAY
      
    // };

    //println!("reveal tx: {}", reveal_tx);
    //println!("reveal tx: {}", reveal_tx);

    // make reveal tx sighash type SINGLE | ANYONECANPAY
    //let sighash_type = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY; 




    (reveal_tx,   vec![vec![], vec![], vec![]], a_fee)
  }


}