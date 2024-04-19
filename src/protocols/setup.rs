use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sp_core::{ecdsa, keccak_256, ByteArray, Pair};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::error::Error;
use ark_std::Zero;
use silent_threshold::{
    kzg::KZG10,
    setup::{AggregateKey, PublicKey, SecretKey},
};

pub const K: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SilentThresholdEncryptionKeypair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Clone)]
pub enum Curve {
    BLS12_381,
    BN254,
}

#[derive(Clone)]
pub struct SilentThresholdEncryptionSetupExtraParams {
    job_id: u64,
    n: u32,
    i: u32,
    t: u32,
    curve: Curve,
    user_id_mapping: Arc<std::collections::HashMap<UserID, ecdsa::Public>>,
    my_id: ecdsa::Public,
}

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::SilentThresholdEncryptionSetupProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<SilentThresholdEncryptionSetupExtraParams, gadget_common::Error> {
    if let jobs::JobType::DKGTSSPhaseOne(p1_job) = job.job_type {
        // Get the participants for the threshold encryption service
        let participants = job.participants_role_ids.clone();
        let user_id_to_account_id_mapping = Arc::new(
            participants
                .clone()
                .into_iter()
                .enumerate()
                .map(|r| (r.0 as UserID, r.1))
                .collect(),
        );

        // Find the index of the current party
        let i = p1_job
            .participants
            .0
            .iter()
            .position(|p| p.0 == config.account_id.0)
            .expect("Should exist") as u16;

        let t = p1_job.threshold;
        let n = p1_job.participants.0.len() as u32;

        Ok(SilentThresholdEncryptionSetupExtraParams {
            job_id: job.job_id,
            n,
            i: i as _,
            t: t as _,
            curve: Curve::BLS12_381,
            user_id_mapping: user_id_to_account_id_mapping,
            my_id: config.key_store.pair().public(),
        })
    } else {
        Err(gadget_common::Error::ClientError {
            err: "The supplied job is not a phase 1 job".to_string(),
        })
    }
}

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::SilentThresholdEncryptionSetupProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: SilentThresholdEncryptionSetupExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let result = Arc::new(Mutex::new(None));
    let result_clone = result.clone();
    let logger = config.logger.clone();
    let logger_clone = logger.clone();
    let network = config.clone();
    let keystore = config.key_store.clone();
    let keystore_clone = keystore.clone();
    let client = config.pallet_tx.clone();
    let SilentThresholdEncryptionSetupExtraParams {
        job_id,
        n,
        i,
        t,
        curve,
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
            /// The protocol for Silent Threshold Encryption Setup does not require interaction
            /// between the parties or the network. Simply, each party is required to generate
            /// a key pair and submit the public key to the network.
            // TODO: Communicate the parameters amongst the parties out-of-band.
            let output: SilentThresholdEncryptionKeypair = match curve {
                Curve::BLS12_381 => {
                    protocol::<_, ark_bls12_381::Bls12_381>(n, i, t, &logger, &keystore_clone)
                        .await?
                }
                Curve::BN254 => {
                    protocol::<_, ark_bn254::Bn254>(n, i, t, &logger, &keystore_clone).await?
                }
            };
            result.lock().await.replace(output);
            Ok(())
        })
        .post(async move {
            /// The post hook is responsible for saving the state of the party after the protocol
            /// and submitting the result to the network. The state that is saved in the keystore
            /// contains the secret key of the party and should not be shared with anyone or submitted
            /// onchain. The only thing that we need to submit onchain is the public key.
            if let Some(key) = result_clone.lock().await.take() {
                keystore
                    .set_job_result(job_id, &key)
                    .await
                    .map_err(|err| JobError {
                        reason: err.to_string(),
                    })?;

                let job_result_for_pallet =
                    jobs::JobResult::DKGPhaseOne(DKGTSSKeySubmissionResult {
                        signature_scheme: DigitalSignatureScheme::SchnorrSecp256k1,
                        key: BoundedVec(key.public_key),
                        participants: BoundedVec(vec![BoundedVec(participants)]),
                        signatures: BoundedVec(vec![]),
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

/// `party_id`: Should be in the range [0, n). For the DKG, should be our index in the best
/// authorities starting from 0.
///
/// Returns the state of the party after the protocol has finished. This should be saved to the keystore and
/// later used for signing
#[allow(clippy::too_many_arguments)]
pub async fn protocol<KBE: KeystoreBackend, E: Pairing>(
    n: u32,
    party_id: u32,
    t: u32,
    logger: &DebugLogger,
    key_store: &ECDSAKeyStore<KBE>,
) -> Result<SilentThresholdEncryptionKeypair, JobError> {
    let mut rng = ark_std::test_rng();
    let params =
        KZG10::<E, DensePolynomial<<E as Pairing>::ScalarField>>::setup(n as usize, &mut rng)
            .unwrap();
    let sk: SecretKey<E> = SecretKey::<E>::new(&mut rng);
    let pk: PublicKey<E> = sk.get_pk(party_id as usize, &params, n as usize);

    let secret_key = to_bytes(sk);
    let public_key = to_bytes(pk);

    Ok(SilentThresholdEncryptionKeypair {
        secret_key,
        public_key,
    })
}

/// Serialize this to a vector of bytes.
pub fn to_bytes<T: CanonicalSerialize>(elt: T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(elt.compressed_size());

    <T as CanonicalSerialize>::serialize_compressed(&elt, &mut bytes).unwrap();

    bytes
}

/// Deserialize this from a slice of bytes.
pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> T {
    <T as CanonicalDeserialize>::deserialize_compressed(&mut &bytes[..]).unwrap()
}
