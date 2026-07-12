//! Durable OAuth client, authorization-code, and opaque token bindings.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pairing::{self, PairingError};
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum OAuthError {
    #[error("OAuth client not found: {0}")]
    ClientNotFound(String),
    #[error("invalid or expired authorization code")]
    InvalidCode,
    #[error("invalid or expired access token")]
    InvalidToken,
    #[error("OAuth binding mismatch: {0}")]
    BindingMismatch(String),
    #[error("pairing error: {0}")]
    Pairing(#[from] PairingError),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCodeRequest<'a> {
    pub client_id: &'a str,
    pub pairing_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub resource: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessGrant {
    pub access_token: String,
    pub expires_in: u64,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct TokenBinding {
    pub client_id: String,
    pub pairing_id: String,
    pub lens_id: String,
    pub resource: String,
}

pub fn register_client(
    vault: &Vault,
    client_name: &str,
    redirect_uris: &[String],
) -> Result<OAuthClient, OAuthError> {
    let client_id = format!("client_{}", ulid::Ulid::new());
    vault.conn().execute(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris_json, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            client_id,
            client_name,
            serde_json::to_string(redirect_uris)?,
            chrono::Utc::now().to_rfc3339()
        ],
    )?;
    Ok(OAuthClient {
        client_id,
        client_name: client_name.to_owned(),
        redirect_uris: redirect_uris.to_vec(),
    })
}

pub fn get_client(vault: &Vault, client_id: &str) -> Result<OAuthClient, OAuthError> {
    vault
        .conn()
        .query_row(
            "SELECT client_id, client_name, redirect_uris_json
             FROM oauth_clients WHERE client_id = ?1",
            [client_id],
            |row| {
                let redirects: String = row.get(2)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    redirects,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                OAuthError::ClientNotFound(client_id.to_owned())
            }
            other => OAuthError::Database(other),
        })
        .and_then(|(client_id, client_name, redirects)| {
            Ok(OAuthClient {
                client_id,
                client_name,
                redirect_uris: serde_json::from_str(&redirects)?,
            })
        })
}

pub fn issue_code(
    vault: &Vault,
    request: &AuthorizationCodeRequest<'_>,
) -> Result<String, OAuthError> {
    let pairing = pairing::get(vault, request.pairing_id)?;
    if !pairing.is_active() || pairing.oauth_client_id.as_deref() != Some(request.client_id) {
        return Err(OAuthError::BindingMismatch(
            "pairing is not active for this client".to_owned(),
        ));
    }
    let code = random_secret();
    let expires = chrono::Utc::now() + chrono::Duration::minutes(5);
    vault.conn().execute(
        "INSERT INTO oauth_authorization_codes
           (code_hash, client_id, pairing_id, redirect_uri, code_challenge, resource, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            secret_hash(&code),
            request.client_id,
            request.pairing_id,
            request.redirect_uri,
            request.code_challenge,
            request.resource,
            expires.to_rfc3339()
        ],
    )?;
    Ok(code)
}

pub fn exchange_code(
    vault: &Vault,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier_challenge: &str,
    resource: &str,
) -> Result<AccessGrant, OAuthError> {
    let conn = vault.conn();
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<AccessGrant, OAuthError> {
        let code_hash = secret_hash(code);
        let row = conn
            .query_row(
                "SELECT client_id, pairing_id, redirect_uri, code_challenge, resource,
                        expires_at, used_at
                 FROM oauth_authorization_codes WHERE code_hash = ?1",
                [code_hash.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => OAuthError::InvalidCode,
                other => OAuthError::Database(other),
            })?;
        let expires = row
            .5
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|_| OAuthError::InvalidCode)?;
        if row.6.is_some()
            || chrono::Utc::now() >= expires
            || row.0 != client_id
            || row.2 != redirect_uri
            || row.3 != verifier_challenge
            || row.4 != resource
        {
            return Err(OAuthError::InvalidCode);
        }
        let pairing = pairing::get(vault, &row.1)?;
        if !pairing.is_active() || pairing.oauth_client_id.as_deref() != Some(client_id) {
            return Err(OAuthError::BindingMismatch(
                "owner approval is no longer active".to_owned(),
            ));
        }
        let now = chrono::Utc::now();
        let token_expires = now + chrono::Duration::minutes(pairing.ttl_minutes as i64);
        let access_token = random_secret();
        conn.execute(
            "UPDATE oauth_authorization_codes SET used_at = ?1 WHERE code_hash = ?2",
            rusqlite::params![now.to_rfc3339(), code_hash],
        )?;
        conn.execute(
            "INSERT INTO oauth_access_tokens
               (token_hash, client_id, pairing_id, lens_id, resource, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                secret_hash(&access_token),
                client_id,
                pairing.id,
                pairing.lens_id,
                resource,
                now.to_rfc3339(),
                token_expires.to_rfc3339()
            ],
        )?;
        Ok(AccessGrant {
            access_token,
            expires_in: (pairing.ttl_minutes as u64) * 60,
            scope: format!("lens:{}", pairing.lens_id),
        })
    })();
    match result {
        Ok(grant) => {
            conn.execute_batch("COMMIT")?;
            Ok(grant)
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub fn validate_token(
    vault: &Vault,
    access_token: &str,
    resource: &str,
) -> Result<TokenBinding, OAuthError> {
    let binding = vault
        .conn()
        .query_row(
            "SELECT client_id, pairing_id, lens_id, resource, expires_at, revoked_at
             FROM oauth_access_tokens WHERE token_hash = ?1",
            [secret_hash(access_token)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => OAuthError::InvalidToken,
            other => OAuthError::Database(other),
        })?;
    let expires = binding
        .4
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| OAuthError::InvalidToken)?;
    if binding.5.is_some() || chrono::Utc::now() >= expires || binding.3 != resource {
        return Err(OAuthError::InvalidToken);
    }
    let pairing = pairing::get(vault, &binding.1)?;
    if !pairing.is_active()
        || pairing.lens_id != binding.2
        || pairing.oauth_client_id.as_deref() != Some(binding.0.as_str())
    {
        return Err(OAuthError::InvalidToken);
    }
    Ok(TokenBinding {
        client_id: binding.0,
        pairing_id: binding.1,
        lens_id: binding.2,
        resource: binding.3,
    })
}

fn random_secret() -> String {
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    blake3::hash(&random).to_hex().to_string()
}

fn secret_hash(secret: &str) -> String {
    blake3::hash(secret.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::lens::{self, LensPolicy};
    use crate::pairing;
    use crate::space::SpaceId;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn code_is_one_time_and_token_is_bound_to_client_lens_resource_and_revocation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("vault");
        let lens_id = lens::create(
            &vault,
            &LensPolicy::new("Remote", vec![SpaceId("space_A".into())]),
        )
        .expect("lens");
        let client = register_client(
            &vault,
            "Remote Agent",
            &["http://127.0.0.1:9911/callback".to_owned()],
        )
        .expect("client");
        let pairing = pairing::approve_remote(
            &vault,
            &lens_id,
            "remote test",
            "Remote Agent",
            10,
            &client.client_id,
        )
        .expect("pairing");
        let resource = "https://tessera.example/mcp";
        let code = issue_code(
            &vault,
            &AuthorizationCodeRequest {
                client_id: &client.client_id,
                pairing_id: &pairing.id,
                redirect_uri: &client.redirect_uris[0],
                code_challenge: "challenge",
                resource,
            },
        )
        .expect("code");
        let grant = exchange_code(
            &vault,
            &code,
            &client.client_id,
            &client.redirect_uris[0],
            "challenge",
            resource,
        )
        .expect("exchange");
        assert_eq!(grant.scope, format!("lens:{}", lens_id.0));
        assert!(matches!(
            exchange_code(
                &vault,
                &code,
                &client.client_id,
                &client.redirect_uris[0],
                "challenge",
                resource,
            ),
            Err(OAuthError::InvalidCode)
        ));
        let binding = validate_token(&vault, &grant.access_token, resource).expect("token");
        assert_eq!(binding.client_id, client.client_id);
        assert_eq!(binding.pairing_id, pairing.id);
        assert_eq!(binding.lens_id, lens_id.0);
        let stored_code: String = vault
            .conn()
            .query_row(
                "SELECT code_hash FROM oauth_authorization_codes",
                [],
                |row| row.get(0),
            )
            .expect("stored code hash");
        let stored_token: String = vault
            .conn()
            .query_row("SELECT token_hash FROM oauth_access_tokens", [], |row| {
                row.get(0)
            })
            .expect("stored token hash");
        assert_ne!(stored_code, code);
        assert_ne!(stored_token, grant.access_token);
        assert!(matches!(
            validate_token(&vault, &grant.access_token, "https://other.example/mcp"),
            Err(OAuthError::InvalidToken)
        ));
        pairing::revoke(&vault, &pairing.id).expect("revoke");
        assert!(validate_token(&vault, &grant.access_token, resource).is_err());
    }
}
