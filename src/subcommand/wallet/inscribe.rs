use std::{borrow::Borrow, io::Read};

use bitcoin::{psbt::PartiallySignedTransaction, EcdsaSig, SchnorrSig, SigHashType};

use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
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

#[derive(Serialize)]
struct Output {
  commit: Txid,
  inscription: InscriptionId,
  reveal: Txid,
  fees: u64,
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

    let inscriptions = index.get_inscriptions(None)?;

    let commit_tx_change = [get_change_address(&client)?, get_change_address(&client)?];

    let reveal_tx_destination = self
      .destination
      .map(Ok)
      .unwrap_or_else(|| get_change_address(&client))?;

    let (unsigned_commit_tx, reveal_tx, recovery_key_pair) =
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
      OutPoint {
        txid: unsigned_commit_tx.txid(),
        vout: 0,
      },
      Amount::from_sat(
        unsigned_commit_tx.output[0 as usize].value,
      ),
    );

    utxos.insert(
      OutPoint {
        txid: unsigned_commit_tx.txid(),
        vout: 1,
      },
      Amount::from_sat(
        unsigned_commit_tx.output[1 as usize].value,
      ),
    );

    let fees =
      Self::calculate_fee(&unsigned_commit_tx, &reveal_tx, &utxos);

    if self.dry_run {
      print_json(Output {
        commit: unsigned_commit_tx.txid(),
        reveal: reveal_tx.txid(),
        inscription: reveal_tx.txid().into(),
        fees,
      })?;
    } else {
      if !self.no_backup {
        Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
      }

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
        .hex;

      let commit = client
        .send_raw_transaction(&signed_raw_commit_tx)
        .context("Failed to send commit transaction")?;

      //let reveal = client
     //   .send_raw_transaction(&reveal_tx)
      //  .context("Failed to send reveal transaction")?;
      
      index.update()?;




    };

    Ok(())
  }

  fn calculate_fee(tx: &Transaction, tx2: &Transaction,  utxos: &BTreeMap<OutPoint, Amount>) -> u64 {
    tx.input
      .iter()
      .map(|txin| 
        utxos.get(&txin.previous_output).unwrap().to_sat())
      .sum::<u64>()
      .checked_add(tx2.input.iter().map(|txin| 
        utxos.get(&txin.previous_output).unwrap().to_sat()).sum::<u64>()).unwrap()  
     
        .checked_sub(tx.output.iter().map(|txout| txout.value).sum::<u64>()).unwrap() 
        .checked_sub(tx2.output.iter().map(|txout| txout.value).sum::<u64>()).unwrap()

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
  ) -> Result<(Transaction, Transaction, TweakedKeyPair /* recovery key pair */)> {
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
        .push_opcode(opcodes::all::OP_CHECKSIG)
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

    let (_, reveal_fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint::null(),
      TxOut {
        script_pubkey: destination.script_pubkey(),
        value: 0,
      },
      &reveal_script,
      commit_tx_address.clone(),
    );

    let unsigned_commit_tx = TransactionBuilder::build_transaction_with_value(
      satpoint,
      inscriptions,
      utxos,
      commit_tx_address.clone(),
      change,
      commit_fee_rate,
      TransactionBuilder::TARGET_POSTAGE,
    )?;
    let (vout, output) = unsigned_commit_tx
      .output
      .iter()
      .enumerate()
      .find(|(_vout, output)| output.script_pubkey == commit_tx_address.clone().script_pubkey())
      .expect("should find sat commit/inscription output");

    let (mut reveal_tx, fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint {
        txid: unsigned_commit_tx.txid(),
        vout: vout.try_into().unwrap(),
      },
      TxOut {
        script_pubkey: destination.clone().script_pubkey(),
        value: output.value 
      },
      &reveal_script,
      commit_tx_address.clone(),
    );
    
    let   (mut vout, mut output) : (usize, TxOut)=  
  
  (0,
    reveal_tx.clone().output[0].clone()   
  );
  
let mut psbt = PartiallySignedTransaction::from_unsigned_tx(reveal_tx.clone()).unwrap();

  let mut sighash_cache = SighashCache::new(&mut reveal_tx);

  let signature_hash = sighash_cache
    .taproot_script_spend_signature_hash(
      vout.clone(),
      &Prevouts::One (vout, output.clone()),
      TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
      SchnorrSighashType::SinglePlusAnyoneCanPay,
    )
    .expect("signature hash should compute");

  let signature = secp256k1.sign_schnorr(
    &secp256k1::Message::from_slice(signature_hash.as_inner())
      .expect("should be cryptographically secure hash"),
    &key_pair,
  );
  let mut sig: bitcoin::secp256k1::schnorr::Signature =   signature.clone();

  let mut signature = sig.as_ref().to_vec();
  signature.push(SchnorrSighashType::SinglePlusAnyoneCanPay as u8);


  let witness = sighash_cache
    .witness_mut(vout)
    .expect("getting mutable witness reference should work");
  witness.push(signature.clone());
  witness.push(reveal_script.clone() ) ;
  witness.push(&control_block.serialize());
  let witness = witness.clone();
let reveal_tx = reveal_tx.clone();
  psbt.unsigned_tx = reveal_tx.clone();

  let mut psbt = psbt.clone();
  psbt.inputs[vout].non_witness_utxo = Some( unsigned_commit_tx.clone());
  psbt.inputs[vout].redeem_script = Some(reveal_script.clone());
  psbt.unsigned_tx.input[vout].witness = witness.clone();
  psbt.inputs[vout].partial_sigs.insert(
    bitcoin::PublicKey::from_slice(&public_key.serialize()).unwrap(),
    EcdsaSig { 
sig:      bitcoin::secp256k1::ecdsa::Signature::from_der(&signature).unwrap(),
      hash_ty:  SigHashType::SinglePlusAnyoneCanPay
    },
  );
  let mut psbt = psbt.clone();

  println!("psbt: {:#?}", psbt.clone());  
  println!("psbt: {:#?}", psbt.clone().extract_tx()); 
  
  println!("psbt: {:#?}", hex::encode(consensus::serialize(&psbt)));


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

    Ok((unsigned_commit_tx, reveal_tx, recovery_key_pair))
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

  fn  build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    input: OutPoint,
    output: TxOut,
    script: &Script,
    commit_tx_address: Address,
  ) -> (Transaction, Amount) {
    let mut reveal_tx = Transaction {
      input: vec![
      TxIn {
      previous_output: input,
      script_sig: script::Builder::new().into_script(),
      witness: Witness::new(),
      sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    },
        TxIn {
          previous_output: OutPoint { 
            txid: Txid::from_hash (Hash::from_inner([1; 32])),
            vout: 1,
          },
          script_sig: Script::new(),
          witness: Witness::new(),  
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        },
        TxIn {
          previous_output: OutPoint { 
            txid: Txid::from_hash (Hash::from_inner([0; 32])),
            vout: 1,
          },
          script_sig: Script::new(),
          witness: Witness::new(),
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, 
        }],
      output: vec![output.clone(),
        
        TxOut {
          script_pubkey: commit_tx_address.script_pubkey(),
          value: 0 
        },
        TxOut {
          script_pubkey: Script::new(),
          value: 6667,
        }   ],
      lock_time: PackedLockTime::ZERO,
      version: 1,
    };

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
    reveal_tx.output[1].value = reveal_tx.output[1]
      .value
      .checked_add (fee.to_sat()).unwrap();
    (reveal_tx, fee)
  }
}
