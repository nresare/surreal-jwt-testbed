use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, anyhow};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::Serialize;
use surrealdb::engine::any;
use surrealdb::engine::any::Any;
use surrealdb::Surreal;
use uuid::Uuid;

const DEFAULT_ENDPOINT: &str = "ws://127.0.0.1:8000";
const DEFAULT_NAMESPACE: &str = "test";
const DEFAULT_DATABASE: &str = "test";
const DEFAULT_ACCESS: &str = "jwt_testbed";
const SIGNING_KEY_PATH: &str = "signing-key.pem";
const JWT_LIFETIME_SECONDS: i64 = 3;
const POST_EXPIRY_PROBE_INTERVAL: StdDuration = StdDuration::from_secs(60);

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    ns: String,
    db: String,
    ac: String,
    roles: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let reusing_existing_key = Path::new(SIGNING_KEY_PATH).exists();
    let endpoint = if reusing_existing_key {
        DEFAULT_ENDPOINT.to_string()
    } else {
        prompt_with_default("WebSocket endpoint", DEFAULT_ENDPOINT)?
    };
    let namespace = if reusing_existing_key {
        DEFAULT_NAMESPACE.to_string()
    } else {
        prompt_with_default("Namespace", DEFAULT_NAMESPACE)?
    };
    let database = if reusing_existing_key {
        DEFAULT_DATABASE.to_string()
    } else {
        prompt_with_default("Database", DEFAULT_DATABASE)?
    };
    let access = if reusing_existing_key {
        DEFAULT_ACCESS.to_string()
    } else {
        prompt_with_default("Access method name", DEFAULT_ACCESS)?
    };

    let signing_key_pem = load_or_create_signing_key_pem()?;
    let secret_key = SecretKey::from_pkcs8_pem(&signing_key_pem)
        .context("failed to parse private key from signing-key.pem")?;
    let verifying_key = secret_key.public_key();
    let public_key_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .context("failed to encode public key as PEM")?;

    if reusing_existing_key {
        log_line(&format!("Reusing signing key from {SIGNING_KEY_PATH}."));
        log_line(&format!(
            "Using defaults without prompting: endpoint={endpoint}, namespace={namespace}, database={database}, access={access}"
        ));
    } else {
        println!("\nRun this in your SurrealDB shell connected to {namespace}/{database}:\n");
        println!(
            "DEFINE ACCESS {access} ON DATABASE TYPE JWT\n    ALGORITHM ES256 KEY '{public_key_pem}';"
        );
        println!("\nThis reproduction keeps the JWT very short-lived and leaves the ACCESS session duration unchanged, so we can observe whether the WebSocket session continues after token expiry.");
        println!("\nWrote private signing key to {SIGNING_KEY_PATH}.\n");
        println!("{signing_key_pem}");

        prompt_continue("Press Enter after you have run the DEFINE ACCESS statement")?;
    }

    let now = Utc::now();
    let exp = now + Duration::seconds(JWT_LIFETIME_SECONDS);
    let claims = Claims {
        iss: "surreal-jwt-testbed".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: exp.timestamp(),
        ns: namespace.clone(),
        db: database.clone(),
        ac: access.clone(),
        roles: vec!["owner".to_string()],
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("surreal-jwt-testbed".to_string());
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(signing_key_pem.as_bytes())
            .context("failed to construct ES256 encoding key from signing PEM")?,
    )
    .context("failed to sign JWT")?;

    log_line(&format!("JWT exp claim: {} ({})", exp.timestamp(), exp.to_rfc3339()));
    log_line(&format!(
        "Attempting WebSocket authentication with a token that expires in about {JWT_LIFETIME_SECONDS} seconds..."
    ));

    let db = any::connect(&endpoint)
        .await
        .with_context(|| format!("failed to connect to websocket endpoint {endpoint}"))?;

    db.authenticate(token.clone())
        .await
        .context("initial authenticate() failed")?;
    log_line("authenticate() succeeded");

    let before_id = format!("before-{}", Uuid::new_v4());
    insert_probe(&db, &before_id, "before-expiry").await?;
    log_line(&format!("insert before expiry succeeded: jwt_probe:{before_id}"));

    let wait_until_expired = (exp - Utc::now())
        .to_std()
        .unwrap_or_else(|_| StdDuration::from_secs(0))
        + StdDuration::from_millis(1200);
    log_line(&format!(
        "Sleeping {:?} so the JWT is definitely expired before the probe loop begins...",
        wait_until_expired
    ));
    tokio::time::sleep(wait_until_expired).await;

    log_line("JWT should now be expired. Probing database writes once per minute until interrupted.");

    let mut attempt = 1_u64;
    loop {
        let probe_id = format!("after-{}-{}", attempt, Uuid::new_v4());
        let phase = format!("after-expiry-attempt-{attempt}");

        match insert_probe(&db, &probe_id, &phase).await {
            Ok(()) => {
                log_line(&format!(
                    "post-expiry probe {attempt} succeeded: jwt_probe:{probe_id}"
                ));
            }
            Err(error) => {
                log_line(&format!(
                    "post-expiry probe {attempt} failed: {error:#}"
                ));
            }
        }

        attempt += 1;
        tokio::time::sleep(POST_EXPIRY_PROBE_INTERVAL).await;
    }
}

async fn insert_probe(db: &Surreal<Any>, id: &str, phase: &str) -> Result<()> {
    let sql =
        "CREATE type::record('jwt_probe', $id) CONTENT { phase: $phase, created_at: time::now() };";
    let mut response = db
        .query(sql)
        .bind(("id", id.to_string()))
        .bind(("phase", phase.to_string()))
        .await
        .with_context(|| format!("query failed for phase {phase}"))?;

    let _: Option<surrealdb::types::Value> = response
        .take(0)
        .map_err(|e| anyhow!("failed to extract create result: {e}"))?;
    Ok(())
}

fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush().context("failed to flush stdout")?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read stdin")?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_continue(message: &str) -> Result<()> {
    print!("{message}: ");
    io::stdout().flush().context("failed to flush stdout")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read stdin")?;
    Ok(())
}

fn log_line(message: &str) {
    println!("[{}] {message}", Utc::now().to_rfc3339());
}

fn load_or_create_signing_key_pem() -> Result<String> {
    if Path::new(SIGNING_KEY_PATH).exists() {
        return fs::read_to_string(SIGNING_KEY_PATH)
            .with_context(|| format!("failed to read {SIGNING_KEY_PATH}"));
    }

    let secret_key = SecretKey::random(&mut OsRng);
    let signing_key_pem = secret_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode private key as PKCS#8 PEM")?
        .to_string();

    fs::write(SIGNING_KEY_PATH, &signing_key_pem)
        .with_context(|| format!("failed to write {SIGNING_KEY_PATH}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(SIGNING_KEY_PATH, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict permissions on {SIGNING_KEY_PATH}"))?;
    }

    Ok(signing_key_pem)
}
