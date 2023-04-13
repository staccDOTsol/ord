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
use bitcoin::{AddressType::P2pkh, psbt::Input,psbt::Output as PsbtOutput, util::psbt::PartiallySignedTransaction, PublicKey};
use std::{ops::Deref, io::BufReader, collections::HashMap, fmt::Debug};
use bitcoin::{consensus::serialize, hashes::hex::ToHex, psbt::{PsbtSighashType, Psbt}, EcdsaSighashType, util::{taproot::TapSighashHash, bip143::SigHashCache}};
use bitcoincore_rpc::{bitcoincore_rpc_json::{SignRawTransactionInput, AddressType, CreateRawTransactionInput, WalletCreateFundedPsbtOptions}, RawTx};
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

    let (unsigned_commit_tx,mut  reveal_tx, recovery_key_pair) =
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
     
     
      // create new psbt with the inputs and outputs
      let psbt = &mut Psbt::from_unsigned_tx(reveal_tx).unwrap();
      // add the witness script


      // add the sighash type
      psbt.inputs[1].sighash_type = Some(EcdsaSighashType::SinglePlusAnyoneCanPay.into());
      // add the utxo
      psbt.inputs[1].non_witness_utxo = Some(bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(&signed_raw_commit_tx.hex).unwrap());
      

      let encoded = Base64Display::with_config(&bitcoin::consensus::encode::serialize(&psbt), base64::STANDARD).to_string();

      let decompiled = bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(&signed_raw_commit_tx.hex).unwrap();


       let signed_psbt = client.wallet_process_psbt(&encoded, Some(true), Some(EcdsaSighashType::SinglePlusAnyoneCanPay.into()), None).unwrap().psbt;
      // base64 decode the psbt
      let test = base64::decode(signed_psbt.clone()).unwrap();
      // deserialize the psbt
      let test = bitcoin::consensus::encode::deserialize::<bitcoin::util::psbt::PartiallySignedTransaction>(&test).unwrap();
      // serialize the psbt
     
      let didwewin: Transaction   =   test.extract_tx().into();

// write to file
println!("{}", signed_psbt  );
let file = File::create("reveals/".to_owned()+&decompiled.txid().to_string() + decompiled.output.len().to_string().as_str() + ".psbt").unwrap();

let filewriter = &mut BufWriter::new(file);

writeln!(filewriter, "{}", signed_psbt).unwrap();
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
      .map(|txin| utxos.get(&txin.previous_output).unwrap().to_sat() as f64)
      .sum::<f64>()
      .sub(tx.output.iter().map(|txout| txout.value as f64).sum::<f64>())
      
  }

  fn create_inscription_transactions(
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
  ) -> Result<(Transaction, Transaction, TweakedKeyPair) > {
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

    let (_, _, reveal_fee) = Self::build_reveal_transaction(
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

    let (mut reveal_tx,  witness, fee) = Self::build_reveal_transaction(
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
    // sighash_type = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
    
    let mut revelly = reveal_tx.clone();
    let mut sighash_cache = SighashCache::new( &mut revelly);

/*
    let signature_hash = sighash_cache
      .taproot_script_spend_signature_hash(
        1,
        &Prevouts::All(&[output]),  
        TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
        SchnorrSighashType::SinglePlusAnyoneCanPay, //  
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
*/
    let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

    let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
    assert_eq!(
      Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
        network,
      ),
      commit_tx_address
    );

    Ok((unsigned_commit_tx, reveal_tx , recovery_key_pair ))
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
    output: TxOut,
    script: &Script,
  ) -> (Transaction, Vec<Vec<u8>> , Amount) {
    
    
      // prepend an output with  an ask for 500 000 sats. SIGHASH SINGLE will ensure we get it !
      let mut output2 = TxOut::default();
      output2.value = 6666;
      output2.script_pubkey = Address::from_str("bc1pzjhmz2egst0etq0r6050m32a585nzwmhxjx23txqdyrwr2p83dwqxzj908").unwrap().script_pubkey();
     // create a tx as previous output with a dummy input
     let dummyTx = Transaction {
      input: vec![TxIn {
        previous_output: OutPoint::default(),
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }],
      output: vec![output2.clone()],
      lock_time: PackedLockTime::ZERO,
      version: 1};


     let dummy = TxIn { 
      previous_output: OutPoint { txid: dummyTx.txid(), vout: 0 },
      script_sig: script::Builder::new().into_script(),
      witness: Witness::new(),
      sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    };
    let reveal_tx = Transaction {
      input: vec![dummy, TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        
      }],
      output: vec![output, output2],
      lock_time: PackedLockTime::ZERO,
      version: 1,
      // SINGLE AND ANYONECANPAY
     
    };

    // I can specify sighash types at the time i create the tx
    //let sighash_type = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY;
    


    

    

       let witness: Vec<Vec<u8>> = vec![
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref().to_vec(),
        script.clone().as_ref().to_vec(),
        control_block.serialize().to_vec()
      ];
      
    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      reveal_tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_tx.input[0].witness.push(script);
      reveal_tx.input[0].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_tx.vsize())
    };

    (reveal_tx, witness, fee)
  }
}
