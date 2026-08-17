use base64::Engine;
use hc_seed_bundle::dependencies::one_err::OneErr;
use hc_seed_bundle::{LockedSeedCipher, SharedLockedArray, UnlockedSeedBundle};
use holo_hash::{AgentPubKeyB64, DnaHashB64};
use holochain_client::{
    AgentPubKey, AppInfo, CellInfo, ConductorApiError, InstallAppPayload, SerializedBytes,
};
use holochain_types::app::{InstalledAppId, RoleSettings};
use holochain_types::prelude::{
    AppBundleSource, AppManifest, DnaModifiersOpt, RoleName, RoleSettingsMap, UnsafeBytes,
    YamlProperties,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum UnytCtlError {
    #[error("Invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("An hc_seed_bundle crypto operation failed: {0}")]
    CryptoError(#[from] OneErr),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error(transparent)]
    HttpRequestFailed(#[from] reqwest::Error),

    #[error("Client error: {0}")]
    ClientError(#[from] ConductorApiError),

    #[error(transparent)]
    JsonError(#[from] serde_json::error::Error),

    #[error(transparent)]
    YamlError(#[from] yaml_serde::Error),

    #[error("Bundle error: {0}")]
    BundleError(#[from] holochain_types::prelude::AppBundleError),

    #[error("Error: {0}")]
    Other(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SeedBundle {
    raw_pubkey: String,
    agent_pubkey: AgentPubKeyB64,
    bundle: String,
}

impl SeedBundle {
    pub fn new(agent_pubkey: AgentPubKey, bundle: Box<[u8]>) -> Self {
        Self {
            raw_pubkey: base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(agent_pubkey.get_raw_32()),
            bundle: base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&bundle),
            agent_pubkey: AgentPubKeyB64::from(agent_pubkey),
        }
    }

    pub fn to_json(self) -> serde_json::Result<String> {
        serde_json::to_string(&self)
    }
}

/// Create a seed bundle containing an agent keypair.
pub async fn create_seed_bundle(passphrase: SharedLockedArray) -> Result<SeedBundle, OneErr> {
    let bundle = UnlockedSeedBundle::new_random().await?;

    let agent_key = AgentPubKey::from_raw_32(bundle.get_sign_pub_key().to_vec());

    let locked = bundle.lock().add_pwhash_cipher(passphrase).lock().await?;

    Ok(SeedBundle::new(agent_key, locked))
}

#[derive(Debug, Serialize)]
pub struct BareSigningKeypair {
    public_key: AgentPubKeyB64,

    seed_hex: String,
}

impl BareSigningKeypair {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self)
    }
}

pub async fn create_bare_signing_keypair() -> Result<BareSigningKeypair, UnytCtlError> {
    let bundle = UnlockedSeedBundle::new_random().await?;

    let public_key =
        AgentPubKeyB64::from(AgentPubKey::from_raw_32(bundle.get_sign_pub_key().to_vec()));
    // `hex::encode` takes `impl AsRef<[u8]>`, so clippy wants the borrow dropped.
    // Don't: the guard derefs to `[u8; 32]`, which is `Copy`, so `*guard` would copy
    // the seed out of libsodium's `sodium_malloc` region onto the stack, losing the
    // mlock, the `mprotect_noaccess` on guard drop, and the zero-on-free.
    #[allow(clippy::needless_borrows_for_generic_args)]
    let seed_hex = hex::encode(&*bundle.get_seed().lock().expect("Poisoned").lock());

    Ok(BareSigningKeypair {
        public_key,
        seed_hex,
    })
}

#[derive(Debug, Serialize)]
struct JoinRequest {
    agent_key: AgentPubKeyB64,
}

#[derive(Debug, Deserialize)]
struct JoinResponseChallengeMetadata {
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct JoinResponseChallenge {
    id: String,
    #[serde(rename = "type")]
    typ: String,
    metadata: Option<JoinResponseChallengeMetadata>,
}

#[derive(Debug, Deserialize)]
struct JoinResponse {
    session: String,
    status: String,
    reason: Option<String>,
    challenges: Option<Vec<JoinResponseChallenge>>,
}

#[derive(Debug, Serialize)]
struct VerifyRequest {
    challenge_id: String,
    response: String,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    status: String,
}

pub async fn joining_service_join(
    joining_service_url: String,
    seed_bundle: String,
    seed_bundle_passphrase: SharedLockedArray,
) -> Result<ProvisionResponse, UnytCtlError> {
    let joining_service_url = url::Url::parse(&joining_service_url)?;

    let bundle_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(seed_bundle.as_bytes())?;
    let mut bundle = UnlockedSeedBundle::from_locked(&bundle_bytes).await?;

    if bundle.is_empty() || bundle.len() != 1 {
        return Err(UnytCtlError::Other(
            "Expected exactly one item in the seed bundle".to_string(),
        ));
    };

    let unlocked = match bundle.remove(0) {
        LockedSeedCipher::PwHash(inner) => inner.unlock(seed_bundle_passphrase).await?,
        _ => {
            return Err(UnytCtlError::Other(
                "Unexpected seed bundle type that was not generated by this tool".to_owned(),
            ));
        }
    };

    let agent_key = AgentPubKeyB64::new(AgentPubKey::from_raw_32(
        unlocked.get_sign_pub_key().to_vec(),
    ));

    // Now that we know the passphrase is correct, we can continue to contact the joining service.
    let join_url = joining_service_url.join("/v1/join")?;
    let client = reqwest::Client::new();
    let response = client
        .post(join_url.clone())
        .json(&JoinRequest { agent_key })
        .send()
        .await?;

    if response.status() != StatusCode::CREATED && response.status() != StatusCode::OK {
        return Err(UnytCtlError::Other(format!(
            "Join failed when contacting {}: {} - {}",
            join_url,
            response.status(),
            response.text().await?
        )));
    }

    let response: JoinResponse = response.json().await?;

    if response.status == "pending" {
        // We need to complete the challenge

        let Some(challenges) = response.challenges else {
            return Err(UnytCtlError::Other(
                "Join status is pending but challenges are missing".to_string(),
            ));
        };

        if challenges.is_empty() {
            return Err(UnytCtlError::Other(
                "Join status is pending but no challenges were sent".to_string(),
            ));
        }

        let Some(allow_list_challenge) = challenges.iter().find(|c| c.typ == "agent_allow_list")
        else {
            return Err(UnytCtlError::Other(
                "No allow list challenges were found".to_string(),
            ));
        };

        let Some(nonce) = allow_list_challenge
            .metadata
            .as_ref()
            .map(|m| m.nonce.clone())
        else {
            return Err(UnytCtlError::Other(
                "No nonce found in allow_list".to_string(),
            ));
        };

        let nonce = base64::prelude::BASE64_STANDARD.decode(nonce.as_bytes())?;
        let signature = unlocked.sign_detached(nonce.into()).await?;

        let signature = base64::prelude::BASE64_STANDARD.encode(signature.as_slice());

        let verify_url =
            joining_service_url.join(&format!("/v1/join/{}/verify", response.session))?;
        let response = client
            .post(verify_url)
            .json(&VerifyRequest {
                challenge_id: allow_list_challenge.id.clone(),
                response: signature,
            })
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            let msg = response.text().await?;
            return Err(UnytCtlError::Other(format!("Verification failed: {}", msg)));
        }

        let response: VerifyResponse = response.json().await?;

        if response.status != "ready" {
            return Err(UnytCtlError::Other(format!(
                "Verification failed: {}",
                response.status
            )));
        }
    } else if response.status == "ready" {
        // Already joined, can just look up the content
    } else {
        return Err(UnytCtlError::Other(format!(
            "Unexpected response status: {} - {:?}",
            response.status, response.reason
        )));
    }

    let response = get_provisioned_join(&client, joining_service_url, response.session).await?;

    Ok(response)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionResponseDnaModifiers {
    network_seed: Option<String>,
    properties: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionResponse {
    membrane_proofs: Option<HashMap<String, String>>,
    dna_modifiers: Option<ProvisionResponseDnaModifiers>,
}

impl ProvisionResponse {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

async fn get_provisioned_join(
    client: &reqwest::Client,
    joining_service_url: Url,
    session_id: String,
) -> Result<ProvisionResponse, UnytCtlError> {
    let provision_url = joining_service_url.join(&format!("/v1/join/{session_id}/provision"))?;

    let response = client.get(provision_url).send().await?;

    if response.status() != StatusCode::OK {
        let msg = response.text().await?;
        return Err(UnytCtlError::Other(format!(
            "Failed to get provision: {}",
            msg
        )));
    }

    let response: ProvisionResponse = response.json().await?;

    Ok(response)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CellInfoSummary {
    name: String,
    dna_hash: DnaHashB64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppInfoSummary {
    installed_app_id: InstalledAppId,
    agent_pub_key: AgentPubKeyB64,
    cells: BTreeMap<RoleName, Vec<CellInfoSummary>>,
    manifest: AppManifest,
}

impl AppInfoSummary {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

impl From<AppInfo> for AppInfoSummary {
    fn from(app_info: AppInfo) -> Self {
        AppInfoSummary {
            installed_app_id: app_info.installed_app_id,
            agent_pub_key: AgentPubKeyB64::from(app_info.agent_pub_key.clone()),
            cells: app_info
                .cell_info
                .iter()
                .map(|(role_name, infos)| {
                    (
                        role_name.clone(),
                        infos
                            .iter()
                            .filter_map(|i| match i {
                                CellInfo::Provisioned(p) => Some(CellInfoSummary {
                                    name: p.name.clone(),
                                    dna_hash: DnaHashB64::from(p.cell_id.dna_hash().clone()),
                                }),
                                _ => None,
                            })
                            .collect(),
                    )
                })
                .collect(),
            manifest: app_info.manifest,
        }
    }
}

pub async fn install_happ(
    admin_ws: SocketAddr,
    admin_ws_origin: Option<String>,
    happ_path: PathBuf,
    existing_agent: AgentPubKeyB64,
    join_payload_path: PathBuf,
) -> Result<AppInfoSummary, UnytCtlError> {
    let join_payload = std::fs::read_to_string(join_payload_path)?;
    let join_payload: ProvisionResponse = serde_json::from_str(&join_payload)?;

    let admin_ws = holochain_client::AdminWebsocket::connect(admin_ws, admin_ws_origin).await?;

    let props = join_payload
        .dna_modifiers
        .as_ref()
        .and_then(|m| m.properties.as_ref().map(yaml_serde::to_value))
        .transpose()?
        .map(YamlProperties::new);

    let mut role_settings: RoleSettingsMap = HashMap::new();

    // Set membrane proofs for any roles that we have membrane proofs for
    if let Some(membrane_proofs) = join_payload.membrane_proofs {
        for (role, proof) in membrane_proofs {
            let role_settings =
                role_settings
                    .entry(role)
                    .or_insert_with(|| RoleSettings::Provisioned {
                        membrane_proof: None,
                        modifiers: None,
                        init_properties: None,
                    });

            match role_settings {
                RoleSettings::Provisioned {
                    membrane_proof,
                    modifiers,
                    ..
                } => {
                    let proof_bytes = base64::prelude::BASE64_STANDARD.decode(proof)?;
                    *membrane_proof = Some(Arc::new(SerializedBytes::from(UnsafeBytes::from(
                        proof_bytes,
                    ))));

                    *modifiers = Some(DnaModifiersOpt {
                        network_seed: None,
                        properties: props.clone(),
                    })
                }
                _ => {
                    unreachable!();
                }
            }
        }
    }

    let response = admin_ws
        .install_app(InstallAppPayload {
            source: AppBundleSource::Path(happ_path),
            agent_key: Some(existing_agent.into()),
            installed_app_id: None,
            network_seed: join_payload
                .dna_modifiers
                .and_then(|m| m.network_seed)
                .filter(|s| !s.is_empty()),
            roles_settings: Some(role_settings),
            ignore_genesis_failure: false,
            // TODO make this a parameter so that the caller can specify a restore.
            restore_from_dht: false,
        })
        .await?;

    Ok(response.into())
}

pub async fn lair_sign_base64(
    agent_pubkey: AgentPubKeyB64,
    pass_locked: SharedLockedArray,
    lair_url: String,
    data: String,
) -> Result<String, UnytCtlError> {
    let client =
        lair_keystore_api::ipc_keystore_connect(Url::parse(&lair_url)?, pass_locked).await?;

    let data = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(data.as_bytes())?;
    let agent_pubkey: AgentPubKey = agent_pubkey.into();
    let pubkey: [u8; hc_seed_bundle::dependencies::sodoken::sign::PUBLICKEYBYTES] =
        agent_pubkey.get_raw_32().try_into().unwrap();
    let signature = client
        .sign_by_pub_key(pubkey.into(), None, Arc::from(data))
        .await?;

    Ok(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(signature.as_slice()))
}
