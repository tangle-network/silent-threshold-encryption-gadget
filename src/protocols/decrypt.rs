use ark_ec::pairing::Pairing;
use futures::{SinkExt, StreamExt};
use gadget_common::client::ClientWithApi;
use gadget_common::config::Network;
use gadget_common::gadget::message::UserID;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::{DebugLogger, GadgetProtocolMessage, WorkManager};
use gadget_common::prelude::{ECDSAKeyStore, JobError};
use gadget_common::tangle_runtime::*;
use gadget_common::utils::recover_ecdsa_pub_key;
use gadget_common::{
    BuiltExecutableJobWrapper, JobBuilder, ProtocolWorkManager, WorkManagerInterface,
};
use hashbrown::HashMap;
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use silent_threshold::decryption::agg_dec;
use silent_threshold::encryption::Ciphertext;
use silent_threshold::setup::{AggregateKey, SecretKey};
use sp_core::{ecdsa, keccak_256, ByteArray, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

use super::setup::{from_bytes, SilentThresholdEncryptionKeypair};

pub const K: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryption<E: Pairing>(pub <E as Pairing>::G2);

#[derive(Clone)]
pub struct SilentThresholdDecryptionExtraParams {
    user_id_mapping: Arc<std::collections::HashMap<UserID, ecdsa::Public>>,
    my_id: ecdsa::Public,
    key_pair: SilentThresholdEncryptionKeypair,
    message_to_decrypt: Vec<u8>,
    agg_key: Vec<u8>,
    params: Vec<u8>,
    n: u32,
    t: u32,
    job_id: u64,
}

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::WstsSigningProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<SilentThresholdDecryptionExtraParams, gadget_common::Error> {
    let job_id = job.job_id;
    if let Some(jobs::JobType::DKGTSSPhaseOne(DKGTSSPhaseOneJobType { threshold, .. })) =
        job.phase1_job
    {
        let participants = job.participants_role_ids.clone();
        let n = participants.len();
        let user_id_to_account_id_mapping = Arc::new(
            participants
                .clone()
                .into_iter()
                .enumerate()
                .map(|r| (r.0 as UserID, r.1))
                .collect(),
        );

        let jobs::JobType::DKGTSSPhaseTwo(DKGTSSPhaseTwoJobType {
            phase_one_id,
            submission,
            ..
        }) = job.job_type
        else {
            panic!("Invalid job type for WSTS signing")
        };
        let my_id = config.key_store.pair().public();
        let keygen_state = config
            .key_store
            .get_job_result(phase_one_id)
            .await?
            .ok_or_else(|| gadget_common::Error::ClientError {
                err: format!("Unable to find stored job result for previous job {phase_one_id}"),
            })?;

        Ok(SilentThresholdDecryptionExtraParams {
            user_id_mapping: user_id_to_account_id_mapping,
            my_id,
            key_pair: keygen_state,
            message_to_decrypt: submission.0,
            agg_key: submission.0,
            params: submission.0,
            n: n as _,
            t: threshold as _,
            job_id,
        })
    } else {
        Err(gadget_common::Error::ClientError {
            err: "Invalid job type".to_string(),
        })
    }
}

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::SilentThresholdDecryptionProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: SilentThresholdDecryptionExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let result = Arc::new(Mutex::new(None));
    let result_clone = result.clone();
    let logger = config.logger.clone();
    let logger_clone = logger.clone();
    let network = config.clone();
    let keystore = config.key_store.clone();
    let keystore_clone = keystore.clone();
    let client = config.pallet_tx.clone();
    let SilentThresholdDecryptionExtraParams {
        job_id,
        n,
        t,
        key_pair,
        message_to_decrypt,
        agg_key,
        params,
        user_id_mapping,
        my_id,
    } = additional_params;

    let participants = user_id_mapping
        .keys()
        .copied()
        .map(|r| r as u8)
        .collect::<Vec<u8>>();

    Ok(JobBuilder::new()
        .protocol(async move {
            let (tx0, rx0, tx1, rx1) =
                gadget_common::channels::create_job_manager_to_async_protocol_channel_split::<
                    _,
                    PartialDecryption,
                    PartialDecryption,
                >(
                    protocol_message_channel,
                    associated_block_id,
                    associated_retry_id,
                    associated_session_id,
                    associated_task_id,
                    user_id_mapping,
                    my_id,
                    network,
                    logger.clone(),
                );
            let output = protocol(
                key_pair,
                message_to_decrypt,
                agg_key,
                params,
                n,
                i,
                t,
                tx0,
                rx0,
                tx1,
                rx1,
                &logger,
                &keystore_clone,
            )
            .await?;
            result.lock().await.replace(output);

            Ok(())
        })
        .post(async move {
            if let Some((state, signatures)) = result_clone.lock().await.take() {
                keystore
                    .set_job_result(job_id, &state)
                    .await
                    .map_err(|err| JobError {
                        reason: err.to_string(),
                    })?;

                let job_result_for_pallet =
                    jobs::JobResult::DKGPhaseOne(DKGTSSKeySubmissionResult {
                        signature_scheme: DigitalSignatureScheme::SchnorrSecp256k1,
                        key: BoundedVec(state.public_key_frost_format),
                        participants: BoundedVec(vec![BoundedVec(participants)]),
                        signatures: BoundedVec(signatures),
                        threshold: t as _,
                        chain_code: None,
                        __ignore: Default::default(),
                    });

                client
                    .submit_job_result(
                        RoleType::Tss(roles::tss::ThresholdSignatureRoleType::WstsV2),
                        job_id,
                        job_result_for_pallet,
                    )
                    .await
                    .map_err(|err| JobError {
                        reason: err.to_string(),
                    })?;
            }

            logger_clone.info("Finished AsyncProtocol - WSTS Keygen");
            Ok(())
        })
        .build())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryptionMessage {
    pub sender: u32,
    pub partial_decryption: Vec<u8>,
}

/// `party_id`: Should be in the range [0, n). For the DKG, should be our index in the best
/// authorities starting from 0.
///
/// Returns the state of the party after the protocol has finished. This should be saved to the keystore and
/// later used for signing
#[allow(clippy::too_many_arguments)]
pub async fn protocol<KBE: KeystoreBackend, E: Pairing>(
    key_pair: SilentThresholdEncryptionKeypair,
    message_to_decrypt: Vec<u8>,
    agg_key: Vec<u8>,
    params: Vec<u8>,
    n: u32,
    party_id: u32,
    t: u32,
    tx_to_network: futures::channel::mpsc::UnboundedSender<PartialDecryption>,
    rx_from_network: futures::channel::mpsc::UnboundedReceiver<std::io::Result<PartialDecryption>>,
    tx_to_network_broadcast: tokio::sync::mpsc::UnboundedSender<PartialDecryption>,
    mut rx_from_network_broadcast: UnboundedReceiver<PartialDecryption>,
    logger: &DebugLogger,
    key_store: &ECDSAKeyStore<KBE>,
) -> Result<(), JobError> {
    // Deserialize the secret key
    let secret_key: SecretKey<E> = from_bytes(&key_pair.secret_key);
    let ct: Ciphertext<E> = from_bytes(&message_to_decrypt);
    let p_decryption = secret_key.partial_decryption(&ct);

    let message = PartialDecryptionMessage {
        sender: party_id,
        partial_decryption: to_bytes(&p_decryption),
    };

    // Send the message
    tx_to_network.send(message).await.map_err(|err| JobError {
        reason: format!("Error sending Partial decryption message: {err:?}"),
    })?;

    let mut partial_decryptions: HashMap<u32, PartialDecryption<E>> = HashMap::new();

    partial_decryptions.insert(party_id, p_decryption);

    // We need t+1 partial decrpytions
    while partial_decryptions.len() < (t + 1) as usize {
        match rx_from_network.next().await {
            Some(Ok(PartialDecryptionMessage {
                sender: party_id_recv,
                partial_decryption,
            })) => {
                if party_id != party_id_recv {
                    let p_decryption: PartialDecryption<E> = from_bytes(&partial_decryption);
                    partial_decryptions.insert(party_id_recv, p_decryption);
                }
            }

            Some(evt) => {
                logger.warn(format!(
                    "Received unexpected partial decryption event: {evt:?}"
                ));
            }

            None => {
                return Err(JobError {
                    reason: "NetListen connection died".to_string(),
                })
            }
        }
    }

    // compute the decryption key
    let mut selector: Vec<bool> = Vec::new();
    for i in 0..n {
        if partial_decryptions.contains_key(&i) {
            selector.push(true);
        } else {
            selector.push(false);
        }
    }

    let agg_key: AggregateKey<E> = from_bytes(&agg_key);
    let params: silent_threshold::kzg::UniversalParams<E> = from_bytes(&params);
    let dec_key = agg_dec(&partial_decryptions, &ct, &selector, &agg_key, &params);
    Ok(())
}
