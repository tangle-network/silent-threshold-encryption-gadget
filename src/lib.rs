use gadget_common::full_protocol::SharedOptional;
use gadget_common::generate_protocol;
use gadget_common::prelude::*;
use gadget_common::tangle_runtime::*;
use sp_core::sr25519;

use crate::protocols::setup::SilentThresholdEncryptionSetupExtraParams;

pub mod protocols;

generate_protocol!(
    "Silent-Threhsold-Encryption-Setup-Protocol",
    SilentThresholdEncryptionSetupProtocol,
    SilentThresholdEncryptionSetupExtraParams,
    protocols::setup::generate_protocol_from,
    protocols::setup::create_next_job,
    jobs::JobType::DKGTSSPhaseOne(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::WstsV2)
);

generate_protocol!(
    "Silent-Threshold-Decryption-Protocol",
    SilentThresholdDecryptionProtocol,
    SilentThresholdDecryptionExtraParams,
    protocols::decrypt::generate_protocol_from,
    protocols::decrypt::create_next_job,
    jobs::JobType::DKGTSSPhaseTwo(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::WstsV2)
);

// generate_setup_and_run_command!(SilentThresholdEncryptionSetupProtocol, SilentThresholdDecryptionProtocol);
