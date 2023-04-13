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
use bech32::ToBase32;
use log::kv::ToValue;
use miniscript::ToPublicKey;
use base64::display::Base64Display;
use bitcoin::{AddressType::P2pkh, psbt::Input,psbt::Output as PsbtOutput, util::{psbt::PartiallySignedTransaction, sighash, amount::serde, taproot::TaprootMerkleBranch}, PublicKey, secp256k1::{Parity, ecdsa, schnorr}, EcdsaSig, KeyPair, Sighash, SchnorrSig};
use std::{ops::{Deref, DerefMut}, io::{BufReader, Read}, collections::HashMap, slice, borrow::BorrowMut};
use bitcoin::{consensus::serialize, hashes::hex::ToHex, psbt::{PsbtSighashType, Psbt}, EcdsaSighashType, util::{taproot::TapSighashHash, bip143::SigHashCache}};
use bitcoincore_rpc::{bitcoincore_rpc_json::{SignRawTransactionInput, AddressType, CreateRawTransactionInput, WalletCreateFundedPsbtOptions, Utxo}, RawTx};
use lazy_static::__Deref;
use miniscript::{Segwitv0, psbt::PsbtExt};
use std::{io::{Write, BufWriter}, borrow::Borrow};
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

    let (unsigned_commit_tx,mut  reveal_tx, recovery_key_pair, witness, tapsighashhash , key_pair , control_block,signature, public_key) =
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


    let creator_fees =
      Self::calculate_fee(&unsigned_commit_tx, &utxos);
      
      let minter_fees = Self::calculate_fee(&reveal_tx, &utxos);

    if self.dry_run {
      print_json(Output {
        commit: unsigned_commit_tx.txid(),
        minter_fees,
        creator_fees,
      })?;
    } else {
      if !self.no_backup {
        Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
      }

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None).unwrap()
        ;

      // broadcast commit tx

      let commit_txid = client.send_raw_transaction(&signed_raw_commit_tx.hex).unwrap();
     
      // alright so the goal is to not have to broadcast the reveal tx until the psbt is signed and ready to go
      // so we need to get the psbt from the reveal tx and then sign it and then broadcast it as another user later 

      // update sighash types in reveal tx

      //

      
      let mut psbt: PartiallySignedTransaction = Psbt::from_unsigned_tx(reveal_tx).unwrap();

      

      // set the witness for the reveal tx in index 1
     // let witness_utxo  // ? we don't have the witness utxo for the reveal tx yet
      
      // set the redeem script for the reveal tx in index 1
      
      // witness: [signature, redeem_script, control_block ]
      let witness_vec =witness.to_vec();
      let redeem_script = witness_vec[1].clone();
      let control_block = witness_vec[2].clone();
      let signature = witness_vec[0].clone();
   //   psbt.inputs[1].redeem_script = Some(Script::from(redeem_script)); 
      

      
      
      // sign using sign_raw_transaction_with_wallet
      let hexpsbt = bitcoin::consensus::serialize(&psbt) ;      
      let base64psbt = base64::encode(hexpsbt   );

    let signed_psbt = client.wallet_process_psbt(&base64psbt, Some(true),
    Some( EcdsaSighashType::SinglePlusAnyoneCanPay.into()), None )  .unwrap().psbt;
      // broadcast reveal tx
      let test: Psbt = bitcoin::consensus::deserialize(base64::decode(signed_psbt.clone()).unwrap().as_slice()).unwrap();
        
    ///  let encoded = signed_psbt.clone() ;
    //  println!("reveal txid: {}", reveal_txid);
      println!("commit txid: {}", commit_txid);

      
      let sig = &test.inputs[1].partial_sigs; 
      print!("sig: {}", sig.len());

      let sig = &test.inputs[0].partial_sigs;
      print!("sig: {}", sig.len());

      let decompiled = test.extract_tx().input[1].previous_output;
      println!("{}", decompiled.txid);

      

// write to file
println!("{}", signed_psbt.clone());
let file = File::create("reveals/".to_owned()+&commit_txid.to_string()   + decompiled.vout.to_string().as_str() + ".psbt").unwrap();

let filewriter = &mut BufWriter::new(file);

writeln!(filewriter, "{}", signed_psbt ).unwrap();
print_json(Output {
 commit: commit_txid,
 minter_fees,
 creator_fees,
})?;
};

Ok(())
}

  fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> f64 {
    tx.input
      .iter()
      .map(|txin| utxos.get(&txin.previous_output).unwrap_or(&Amount::ZERO).to_sat() as f64)
      .sum::<f64>()
      .sub(tx.output.iter().map(|txout| txout.value as f64).sum::<f64>())
      
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
        value: output.value,
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
        previous_output: input2,
        script_sig: Script::new(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        
      }, TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }],
      output: vec![ output2, output],
      lock_time: PackedLockTime::ZERO,
      version: 1,
      // SINGLE AND ANYONECANPAY
     
    };
    //println!("reveal tx: {}", reveal_tx);
    //println!("reveal tx: {}", reveal_tx);

    // make reveal tx sighash type SINGLE | ANYONECANPAY
    //let sighash_type = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY; 

    



    

    

       let witness: Vec<Vec<u8>> = vec![
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref().to_vec(),
        script.clone().as_ref().to_vec(),
        control_block.serialize().to_vec()
      ];
      
    let fee = {
      let mut reveal_txx = reveal_tx.clone();

      reveal_txx.input[1].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_txx.input[1].witness.push(script);
      reveal_txx.input[1].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_txx.vsize())
    };

    (reveal_tx, witness, fee)
  }
}
