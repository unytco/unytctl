use base64::Engine;
use hc_seed_bundle::dependencies::one_err::OneErr;
use hc_seed_bundle::{SharedLockedArray, UnlockedSeedBundle};
use holo_hash::AgentPubKeyB64;
use holochain_client::AgentPubKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgenitorBundle {
    agent_pubkey: AgentPubKeyB64,

    bundle: String,
}

impl ProgenitorBundle {
    pub fn new(agent_pubkey: AgentPubKey, bundle: Box<[u8]>) -> Self {
        Self {
            agent_pubkey: AgentPubKeyB64::from(agent_pubkey),
            bundle: base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&bundle),
        }
    }

    pub fn to_json(self) -> serde_json::Result<String> {
        serde_json::to_string(&self)
    }
}

pub async fn create_progenitor(passphrase: SharedLockedArray) -> Result<ProgenitorBundle, OneErr> {
    let bundle = UnlockedSeedBundle::new_random().await?;

    let agent_key = AgentPubKey::from_raw_32(bundle.get_sign_pub_key().to_vec());

    let locked = bundle.lock().add_pwhash_cipher(passphrase).lock().await?;

    Ok(ProgenitorBundle::new(agent_key, locked))
}
