#[cfg(not(target_arch = "wasm32"))]
pub mod c;
mod did_methods;
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod jni;
#[cfg(not(target_arch = "wasm32"))]
pub mod runtime;
#[cfg(not(any(target_arch = "wasm32", target_os = "windows")))]
pub mod ssh_agent;

#[macro_use]
extern crate lazy_static;

pub use crate::did_methods::DID_METHODS;
pub use crate::error::Error;

pub use ssi;
pub use ssi::did::VerificationRelationship;
pub use ssi::did::{
    DIDCreate, DIDDeactivate, DIDDocumentOperation, DIDMethod, DIDRecover, DIDUpdate, Document,
    Source, DIDURL,
};
pub use ssi::did_resolve::resolve_key;
#[cfg(feature = "http-did")]
pub use ssi::did_resolve::HTTPDIDResolver;
pub use ssi::did_resolve::{
    dereference, Content, ContentMetadata, DIDResolver, DereferencingInputMetadata,
    DocumentMetadata, Metadata, ResolutionInputMetadata, ResolutionMetadata, ResolutionResult,
    SeriesResolver,
};
pub use ssi::jsonld::ContextLoader;
pub use ssi::jwk::JWK;
pub use ssi::ldp::ProofPreparation;
pub use ssi::tzkey::jwk_from_tezos_key;
pub use ssi::vc::get_verification_method;
pub use ssi::vc::Credential as VerifiableCredential;
pub use ssi::vc::CredentialOrJWT;
pub use ssi::vc::LinkedDataProofOptions;
pub use ssi::vc::Presentation as VerifiablePresentation;
pub use ssi::vc::VerificationResult;
pub use ssi::vc::URI;
pub use ssi::zcap::{Delegation, Invocation};

use core::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct JWTOrLDPOptions {
    /// Linked data proof options from vc-api (vc-http-api)
    #[serde(flatten)]
    pub ldp_options: LinkedDataProofOptions,
    /// Proof format (not standard in vc-api)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_format: Option<ProofFormat>,
}

impl JWTOrLDPOptions {
    pub fn default_for_vp() -> Self {
        Self {
            ldp_options: LinkedDataProofOptions {
                proof_purpose: Some(VerificationRelationship::Authentication),
                ..Default::default()
            },
            proof_format: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[non_exhaustive]
pub enum ProofFormat {
    /// <https://www.w3.org/TR/vc-data-model/#linked-data-proofs>
    #[serde(rename = "ldp")]
    LDP,
    /// <https://www.w3.org/TR/vc-data-model/#json-web-token>
    #[serde(rename = "jwt")]
    JWT,
}
// ProofFormat implements Display and FromStr for structopt. This should be kept in sync with the
// serde (de)serialization (rename = ...)

impl Default for ProofFormat {
    fn default() -> Self {
        Self::LDP
    }
}

impl std::fmt::Display for ProofFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LDP => write!(f, "ldp"),
            Self::JWT => write!(f, "jwt"),
        }
    }
}

impl FromStr for ProofFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..] {
            "ldp" => Ok(Self::LDP),
            "jwt" => Ok(Self::JWT),
            _ => Err(format!("Unexpected proof format: {}", s))?,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GenerateProofError {
    #[cfg(not(any(target_arch = "wasm32", target_os = "windows")))]
    #[error("Unable to sign: {0}")]
    Sign(#[from] crate::ssh_agent::SignError),
    #[error("SSI Linked Data Proof: {0}")]
    LDP(#[from] ssi::ldp::Error),
    #[error("IO: {0}")]
    IO(#[from] std::io::Error),
    #[error("WASM support for ssh-agent is not enabled")]
    NoWASM,
    #[error("Windows support for ssh-agent is not enabled")]
    NoWindows,
}

pub async fn generate_proof(
    document: &(dyn ssi::ldp::LinkedDataDocument + Sync),
    key: Option<&JWK>,
    options: LinkedDataProofOptions,
    resolver: &dyn DIDResolver,
    context_loader: &mut ContextLoader,
    ssh_agent_sock_path_opt: Option<&str>,
) -> Result<ssi::ldp::Proof, GenerateProofError> {
    use ssi::ldp::LinkedDataProofs;
    let proof = match ssh_agent_sock_path_opt {
        #[cfg(target_arch = "wasm32")]
        Some(_) => {
            return Err(GenerateProofError::NoWASM);
        }
        #[cfg(target_os = "windows")]
        Some(_) => {
            return Err(GenerateProofError::NoWindows);
        }
        #[cfg(not(any(target_arch = "wasm32", target_os = "windows")))]
        Some(sock_path) => {
            use tokio::net::UnixStream;
            let mut ssh_agent_sock = UnixStream::connect(sock_path).await?;
            crate::ssh_agent::generate_proof(
                &mut ssh_agent_sock,
                document,
                options,
                resolver,
                context_loader,
                key,
            )
            .await?
        }
        None => {
            let jwk = key.expect("JWK, Key Path, or SSH Agent option is required.");
            LinkedDataProofs::sign(document, &options, resolver, context_loader, &jwk, None).await?
        }
    };

    Ok(proof)
}

pub async fn issue_presentation(
    presentation: String,
    proof_options: String,
    key: &JWK,
) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation)?;
    //let key: JWK = serde_json::from_str(&key)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    println!("proof options: {}", proof_options);
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ContextLoader::default();
    println!("proof format: {}", proof_format);
    let vp_string = match proof_format {
        ProofFormat::JWT => {
            presentation
                .generate_jwt(Some(&key), &options.ldp_options, resolver)
                .await?
        }
        ProofFormat::LDP => {
            let proof = presentation
                .generate_proof(&key, &options.ldp_options, resolver, &mut context_loader)
                .await?;
            presentation.add_proof(proof);
            serde_json::to_string(&presentation)?
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    Ok(vp_string)
}

// from didkit\lib\web\src\lib.rs
pub async fn verify_presentation(vp_string: &str, proof_options: &str) -> Result<String, Error> {
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result = match proof_format {
        ProofFormat::JWT => {
            VerifiablePresentation::verify_jwt(
                vp_string,
                Some(options.ldp_options),
                resolver,
                &mut context_loader,
            )
            .await
        }
        ProofFormat::LDP => {
            let vp = VerifiablePresentation::from_json_unsigned(vp_string)?;
            vp.verify(Some(options.ldp_options), resolver, &mut context_loader)
                .await
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

// from didkit\lib\web\src\lib.rs
pub async fn issue_credential(
    credential: String,
    proof_options: String,
    key: &JWK,
) -> Result<String, Error> {
    let mut credential = VerifiableCredential::from_json_unsigned(&credential)?;
    //let key: JWK = serde_json::from_str(&key)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let vc_string = match proof_format {
        ProofFormat::JWT => {
            let vc_jwt = credential
                .generate_jwt(Some(&key), &options.ldp_options, resolver)
                .await?;
            vc_jwt
        }
        ProofFormat::LDP => {
            let proof = credential
                .generate_proof(&key, &options.ldp_options, resolver, &mut context_loader)
                .await?;
            credential.add_proof(proof);
            let vc_json = serde_json::to_string(&credential)?;
            vc_json
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    Ok(vc_string)
}

pub async fn verify_credential(vc_string: String, proof_options: String) -> Result<String, Error> {
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result = match proof_format {
        ProofFormat::JWT => {
            VerifiableCredential::verify_jwt(
                &vc_string,
                Some(options.ldp_options),
                resolver,
                &mut context_loader,
            )
            .await
        }
        ProofFormat::LDP => {
            let vc = VerifiableCredential::from_json_unsigned(&vc_string)?;
            vc.verify(Some(options.ldp_options), resolver, &mut context_loader)
                .await
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

// from didkit\lib\web\src\lib.rs
pub async fn key_to_verification_method(method_pattern: String, key: &JWK) -> Result<String, Error> {
    //let key: JWK = serde_json::from_str(&jwk)?;
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(key, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    let did_resolver = DID_METHODS.to_resolver();
    let vm = get_verification_method(&did, did_resolver)
        .await
        .ok_or(Error::UnableToGetVerificationMethod)?;
    Ok(vm)
}

// from didkit\lib\web\src\lib.rs
pub fn key_to_did(method_pattern: String, key: &JWK) -> Result<String, Error> {
    //let key: JWK = serde_json::from_str(&jwk)?;
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(key, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    Ok(did)
}
