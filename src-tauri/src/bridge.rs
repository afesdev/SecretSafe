use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::thread;

use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server, StatusCode};
use uuid::Uuid;

use crate::{
    models::{BridgePairPin, SecretEntryInput},
    vault,
};

const BRIDGE_ADDR: &str = "127.0.0.1:47635";
const PAIR_PIN_TTL_MINUTES: i64 = 180;
const BRIDGE_TOKEN_TTL_MINUTES: i64 = 30;

#[derive(Clone)]
struct AppSession {
    vault_path: String,
    master_password: String,
}

struct BridgeState {
    app_session: Option<AppSession>,
    pair_pin: Option<(String, i64)>,
    active_tokens: HashMap<String, i64>,
}

static BRIDGE_STATE: OnceLock<Mutex<BridgeState>> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchRequest {
    token: String,
    domain: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FillRequest {
    token: String,
    entry_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveRequest {
    token: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: Option<String>,
    group: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairVerifyRequest {
    pin: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairVerifyResponse {
    token: String,
    expires_at_unix: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BridgeEntry {
    id: String,
    title: String,
    username: String,
    url: String,
    group: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FillResponse {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveResponse {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultMetaResponse {
    groups: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    error: String,
}

pub fn start() {
    thread::spawn(|| {
        let server = match Server::http(BRIDGE_ADDR) {
            Ok(server) => server,
            Err(error) => {
                eprintln!("SecretSafe bridge no se pudo iniciar: {error}");
                return;
            }
        };

        for mut request in server.incoming_requests() {
            let method = request.method().clone();
            let path = request.url().to_string();
            let response = match (method, path.as_str()) {
                (Method::Get, "/health") => json_ok(serde_json::json!({
                    "name": "SecretSafe Bridge",
                    "status": "ok",
                    "addr": BRIDGE_ADDR,
                    "sessionActive": bridge_has_session()
                })),
                (Method::Post, "/pair/verify") => {
                    match read_json::<PairVerifyRequest>(&mut request) {
                        Ok(payload) => handle_pair_verify(payload),
                        Err(error) => json_bad_request(error),
                    }
                }
                (Method::Post, "/vault/search") => match read_json::<SearchRequest>(&mut request) {
                    Ok(payload) => handle_search(payload),
                    Err(error) => json_bad_request(error),
                },
                (Method::Post, "/vault/fill") => match read_json::<FillRequest>(&mut request) {
                    Ok(payload) => handle_fill(payload),
                    Err(error) => json_bad_request(error),
                },
                (Method::Post, "/vault/save") => match read_json::<SaveRequest>(&mut request) {
                    Ok(payload) => handle_save(payload),
                    Err(error) => json_bad_request(error),
                },
                (Method::Post, "/vault/meta") => match read_json::<SearchRequest>(&mut request) {
                    Ok(payload) => handle_meta(payload),
                    Err(error) => json_bad_request(error),
                },
                _ => json_not_found("Ruta no soportada"),
            };

            let _ = request.respond(response);
        }
    });
}

pub fn set_active_session(vault_path: String, master_password: String) {
    if let Ok(mut state) = bridge_state().lock() {
        state.app_session = Some(AppSession {
            vault_path,
            master_password,
        });
    }
}

pub fn clear_active_session() {
    if let Ok(mut state) = bridge_state().lock() {
        state.app_session = None;
        state.pair_pin = None;
        state.active_tokens.clear();
    }
}

pub fn create_pair_pin() -> BridgePairPin {
    let now = now_unix();
    if let Ok(mut state) = bridge_state().lock() {
        if let Some((pin, expires_at_unix)) = state.pair_pin.clone() {
            if now <= expires_at_unix {
                return BridgePairPin {
                    pin,
                    expires_at_unix,
                };
            }
        }
        let pin = format!("{:06}", (Uuid::new_v4().as_u128() % 1_000_000) as u32);
        let expires_at_unix = now + time::Duration::minutes(PAIR_PIN_TTL_MINUTES).whole_seconds();
        state.pair_pin = Some((pin.clone(), expires_at_unix));
        return BridgePairPin {
            pin,
            expires_at_unix,
        };
    }

    let pin = format!("{:06}", (Uuid::new_v4().as_u128() % 1_000_000) as u32);
    let expires_at_unix = now + time::Duration::minutes(PAIR_PIN_TTL_MINUTES).whole_seconds();
    BridgePairPin {
        pin,
        expires_at_unix,
    }
}

fn handle_pair_verify(payload: PairVerifyRequest) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut state = match bridge_state().lock() {
        Ok(state) => state,
        Err(_) => return json_bad_request("No se pudo leer estado de bridge".to_string()),
    };

    if state.app_session.is_none() {
        return json_bad_request("Debes desbloquear la bóveda en SecretSafe.".to_string());
    }

    let now = now_unix();
    let Some((pin, expires_at_unix)) = state.pair_pin.clone() else {
        return json_bad_request("No hay PIN activo. Genera uno en la app.".to_string());
    };

    if now > expires_at_unix {
        state.pair_pin = None;
        return json_bad_request("El PIN expiró. Genera uno nuevo.".to_string());
    }

    if payload.pin.trim() != pin {
        return json_unauthorized("PIN inválido");
    }

    let bridge_token = format!("bridge-{}", Uuid::new_v4().simple());
    let token_expires = now + time::Duration::minutes(BRIDGE_TOKEN_TTL_MINUTES).whole_seconds();
    state
        .active_tokens
        .insert(bridge_token.clone(), token_expires);

    json_ok(
        serde_json::to_value(PairVerifyResponse {
            token: bridge_token,
            expires_at_unix: token_expires,
        })
        .unwrap_or_else(|_| serde_json::json!({ "error": "No se pudo serializar respuesta" })),
    )
}

fn handle_search(payload: SearchRequest) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(app_session) = require_valid_token(&payload.token) else {
        return json_unauthorized("Sesión de extensión no válida");
    };

    let domain = payload.domain.trim().to_lowercase();
    if domain.is_empty() {
        return json_bad_request("Dominio requerido".to_string());
    }

    match vault::unlock_vault(&app_session.vault_path, &app_session.master_password) {
        Ok(vault) => {
            let entries = vault
                .entries
                .into_iter()
                .filter(|entry| entry.url.to_lowercase().contains(&domain))
                .map(|entry| BridgeEntry {
                    id: entry.id.to_string(),
                    title: entry.title,
                    username: entry.username,
                    url: entry.url,
                    group: entry.group,
                })
                .collect::<Vec<_>>();

            json_ok(serde_json::json!({ "entries": entries }))
        }
        Err(error) => json_bad_request(error.to_string()),
    }
}

fn handle_fill(payload: FillRequest) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(app_session) = require_valid_token(&payload.token) else {
        return json_unauthorized("Sesión de extensión no válida");
    };

    match vault::unlock_vault(&app_session.vault_path, &app_session.master_password) {
        Ok(vault) => {
            let Some(entry) = vault
                .entries
                .into_iter()
                .find(|entry| entry.id.to_string() == payload.entry_id)
            else {
                return json_not_found("No se encontró la entrada solicitada");
            };

            json_ok(
                serde_json::to_value(FillResponse {
                    username: entry.username,
                    password: entry.password,
                })
                .unwrap_or_else(
                    |_| serde_json::json!({ "error": "No se pudo serializar respuesta" }),
                ),
            )
        }
        Err(error) => json_bad_request(error.to_string()),
    }
}

fn handle_save(payload: SaveRequest) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(app_session) = require_valid_token(&payload.token) else {
        return json_unauthorized("Sesión de extensión no válida");
    };
    if payload.title.trim().is_empty() {
        return json_bad_request("El titulo es obligatorio".to_string());
    }
    if payload.password.is_empty() {
        return json_bad_request("La contraseña es obligatoria".to_string());
    }

    let existing = match vault::unlock_vault(&app_session.vault_path, &app_session.master_password) {
        Ok(vault) => vault.entries,
        Err(error) => return json_bad_request(error.to_string()),
    };
    let normalized_url = payload.url.trim().to_lowercase();
    let normalized_user = payload.username.trim().to_lowercase();
    if !normalized_url.is_empty()
        && existing.iter().any(|item| {
            item.url.trim().to_lowercase() == normalized_url
                && item.username.trim().to_lowercase() == normalized_user
        })
    {
        return json_bad_request(
            "Ya existe un secreto con la misma URL y usuario. Evitamos duplicados.".to_string(),
        );
    }

    let entry = SecretEntryInput {
        title: payload.title.trim().to_string(),
        username: payload.username.trim().to_string(),
        password: payload.password,
        url: payload.url.trim().to_string(),
        notes: payload.notes.unwrap_or_default().trim().to_string(),
        group: payload.group.unwrap_or_else(|| "General".to_string()),
        icon: "auto".to_string(),
        color: "#6366F1".to_string(),
        custom_fields: Vec::new(),
    };

    match vault::add_entry(
        &app_session.vault_path,
        &app_session.master_password,
        entry,
    ) {
        Ok(updated) => {
            let id = updated
                .entries
                .last()
                .map(|item| item.id.to_string())
                .unwrap_or_default();
            json_ok(
                serde_json::to_value(SaveResponse { id }).unwrap_or_else(
                    |_| serde_json::json!({ "error": "No se pudo serializar respuesta" }),
                ),
            )
        }
        Err(error) => json_bad_request(error.to_string()),
    }
}

fn handle_meta(payload: SearchRequest) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(app_session) = require_valid_token(&payload.token) else {
        return json_unauthorized("Sesión de extensión no válida");
    };
    match vault::unlock_vault(&app_session.vault_path, &app_session.master_password) {
        Ok(vault) => json_ok(
            serde_json::to_value(VaultMetaResponse {
                groups: vault.groups,
            })
            .unwrap_or_else(|_| serde_json::json!({ "groups": ["General"] })),
        ),
        Err(error) => json_bad_request(error.to_string()),
    }
}

fn require_valid_token(token: &str) -> Option<AppSession> {
    let now = now_unix();
    let mut state = bridge_state().lock().ok()?;

    state
        .active_tokens
        .retain(|_, expires_at| now <= *expires_at);

    if !state.active_tokens.contains_key(token) {
        return None;
    }

    state.app_session.clone()
}

fn bridge_has_session() -> bool {
    bridge_state()
        .lock()
        .ok()
        .and_then(|state| state.app_session.clone())
        .is_some()
}

fn bridge_state() -> &'static Mutex<BridgeState> {
    BRIDGE_STATE.get_or_init(|| {
        Mutex::new(BridgeState {
            app_session: None,
            pair_pin: None,
            active_tokens: HashMap::new(),
        })
    })
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn read_json<T: for<'de> Deserialize<'de>>(request: &mut tiny_http::Request) -> Result<T, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|error| error.to_string())?;

    serde_json::from_str(&body).map_err(|error| error.to_string())
}

fn json_ok(body: serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(StatusCode(200), body)
}

fn json_bad_request(message: String) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        StatusCode(400),
        serde_json::to_value(ErrorBody { error: message }).unwrap(),
    )
}

fn json_unauthorized(message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        StatusCode(401),
        serde_json::to_value(ErrorBody {
            error: message.to_string(),
        })
        .unwrap(),
    )
}

fn json_not_found(message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        StatusCode(404),
        serde_json::to_value(ErrorBody {
            error: message.to_string(),
        })
        .unwrap(),
    )
}

fn json_response(
    status: StatusCode,
    body: serde_json::Value,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let payload =
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec());
    let mut response = Response::from_data(payload).with_status_code(status);
    if let Ok(header) = Header::from_bytes(b"Content-Type", b"application/json; charset=utf-8") {
        response.add_header(header);
    }
    response
}
