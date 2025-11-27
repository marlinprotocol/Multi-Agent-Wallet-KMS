use anyhow::{Context, Result};
use dotenvy::dotenv;
use ethereum_types::{H160, H256, U256};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

// Enclave defaults so deployments can boot without extra flags.
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_KMS_PATH: &str = "sepolia-wallet";
const KMS_ENDPOINT_PREFIX: &str = "http://127.0.0.1:1101/derive/secp256k1?path=";
const CHAIN_ID_SEPOLIA: u64 = 11155111;
const DEFAULT_GAS_LIMIT: u64 = 21_000;
const DEFAULT_USER_CAP_WEI: &str = "1000000000000000000"; // 1 ETH

fn main() -> Result<()> {
    // Load `.env`, derive the signing key once, then serve HTTP requests forever.
    dotenv().ok();
    let kms_path =
        std::env::var("CONTRACT_KMS_PATH").unwrap_or_else(|_| DEFAULT_KMS_PATH.to_string());
    let rpc_url = std::env::var("SEPOLIA_RPC_URL")
        .context("SEPOLIA_RPC_URL env var is required to reach an Ethereum RPC endpoint")?;
    let listen_addr =
        std::env::var("WALLET_LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());

    let (signing_key, secret_key_bytes) = derive_signing_key(&kms_path)?;
    let address = derive_address(&signing_key.verifying_key());

    println!("wallet address: 0x{:x}", address);

    let service = Arc::new(WalletService::new(
        secret_key_bytes,
        address,
        rpc_url,
        CHAIN_ID_SEPOLIA,
    ));
    let server = Server::http(&listen_addr)
        .map_err(|err| anyhow::anyhow!("unable to bind HTTP server on {listen_addr}: {err}"))?;
    println!("wallet server listening on {listen_addr}");

    // Tiny synchronous HTTP loop – each request handled in its own thread.
    for request in server.incoming_requests() {
        let svc = Arc::clone(&service);
        std::thread::spawn(move || {
            if let Err(err) = handle_request(svc, request) {
                eprintln!("request handling error: {err}");
            }
        });
    }

    Ok(())
}

fn derive_signing_key(kms_path: &str) -> Result<(SigningKey, [u8; 32])> {
    // Pull raw secret bytes from contract KMS; enclave never persists this outside RAM.
    let url = format!("{KMS_ENDPOINT_PREFIX}{kms_path}");
    let response = ureq::get(&url)
        .call()
        .with_context(|| format!("failed to reach contract KMS at {url}"))?;
    let buffer = response
        .into_body()
        .read_to_vec()
        .context("failed to read KMS response body")?;
    let key_slice = buffer
        .get(0..32)
        .ok_or_else(|| anyhow::anyhow!("KMS response did not contain 32 bytes"))?;
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key_slice);
    let signing_key = SigningKey::from_bytes(&key_bytes.into())
        .context("failed to construct signing key from KMS material")?;
    Ok((signing_key, key_bytes))
}

fn derive_address(verifying_key: &VerifyingKey) -> H160 {
    // Standard Ethereum address derivation: keccak(uncompressed_pubkey)[12..32].
    let uncompressed = verifying_key.to_encoded_point(false);
    let public_key = &uncompressed.as_bytes()[1..];
    let hash = Keccak256::digest(public_key);
    H160::from_slice(&hash[12..])
}

fn handle_request(service: Arc<WalletService>, mut request: Request) -> Result<(), WalletError> {
    let method = request.method().clone();
    let path = request.url().trim_start_matches('/').to_string();
    // Simple router – match method + path and defer to WalletService helpers.
    match (method, path.as_str()) {
        (Method::Get, "address") => {
            let payload = AddressResponse {
                address: format!("0x{:x}", service.address()),
            };
            respond_json(request, StatusCode(200), &payload)
        }
        (Method::Get, "balance") => match service.fetch_balance() {
            Ok(balance) => {
                let payload = BalanceResponse {
                    address: format!("0x{:x}", service.address()),
                    balance_wei: balance.to_string(),
                    balance_hex: format!("0x{:x}", balance),
                };
                respond_json(request, StatusCode(200), &payload)
            }
            Err(err) => {
                respond_json(
                    request,
                    StatusCode(500),
                    &ErrorResponse {
                        error: err.to_string(),
                    },
                )?;
                Err(err)
            }
        },
        (Method::Post, "users") => {
            let mut body = String::new();
            request
                .as_reader()
                .read_to_string(&mut body)
                .map_err(|err| WalletError::Transport(err.to_string()))?;
            let onboard: OnboardRequest = serde_json::from_str(&body)
                .map_err(|err| WalletError::Input(format!("invalid onboarding payload: {err}")))?;
            match service.onboard_user(onboard) {
                Ok(response) => respond_json(request, StatusCode(201), &response),
                Err(err) => {
                    respond_json(
                        request,
                        StatusCode(400),
                        &ErrorResponse {
                            error: err.to_string(),
                        },
                    )?;
                    Err(err)
                }
            }
        }
        (Method::Get, _) if path.starts_with("users/") && path.ends_with("/status") => {
            let user_id = path
                .trim_start_matches("users/")
                .trim_end_matches("/status");
            let api_key = match extract_api_key(&request) {
                Some(key) => key,
                None => {
                    respond_json(
                        request,
                        StatusCode(401),
                        &ErrorResponse {
                            error: "missing X-Api-Key header".to_string(),
                        },
                    )?;
                    return Err(WalletError::Unauthorized("missing api key".to_string()));
                }
            };
            match service.authenticate_api_key(&api_key) {
                Ok(session) => match service.user_status(&session, user_id) {
                    Ok(response) => respond_json(request, StatusCode(200), &response),
                    Err(err) => {
                        respond_json(
                            request,
                            StatusCode(404),
                            &ErrorResponse {
                                error: err.to_string(),
                            },
                        )?;
                        Err(err)
                    }
                },
                Err(err) => {
                    respond_json(
                        request,
                        StatusCode(401),
                        &ErrorResponse {
                            error: err.to_string(),
                        },
                    )?;
                    Err(err)
                }
            }
        }
        (Method::Post, "withdraw") => {
            let api_key = match extract_api_key(&request) {
                Some(key) => key,
                None => {
                    respond_json(
                        request,
                        StatusCode(401),
                        &ErrorResponse {
                            error: "missing X-Api-Key header".to_string(),
                        },
                    )?;
                    return Err(WalletError::Unauthorized("missing api key".to_string()));
                }
            };
            let session = match service.authenticate_api_key(&api_key) {
                Ok(s) => s,
                Err(err) => {
                    respond_json(
                        request,
                        StatusCode(401),
                        &ErrorResponse {
                            error: err.to_string(),
                        },
                    )?;
                    return Err(err);
                }
            };

            let mut body = String::new();
            request
                .as_reader()
                .read_to_string(&mut body)
                .map_err(|err| WalletError::Transport(err.to_string()))?;
            let withdraw_req: WithdrawRequest = serde_json::from_str(&body)
                .map_err(|err| WalletError::Input(format!("invalid withdraw payload: {err}")))?;
            match service.withdraw_for_user(&session, withdraw_req) {
                Ok((response, value_spent)) => {
                    service.record_withdrawal(&session.user_id, &value_spent)?;
                    respond_json(request, StatusCode(200), &response)
                }
                Err(err) => {
                    let status = match &err {
                        WalletError::Input(_) => StatusCode(400),
                        WalletError::Rpc(_) => StatusCode(502),
                        WalletError::Transport(_) => StatusCode(502),
                        WalletError::Signing(_) => StatusCode(500),
                        WalletError::Unauthorized(_) => StatusCode(401),
                        WalletError::State(_) => StatusCode(500),
                    };
                    respond_json(
                        request,
                        status,
                        &ErrorResponse {
                            error: err.to_string(),
                        },
                    )?;
                    Err(err)
                }
            }
        }
        (Method::Post, "instructions/strategy") => {
            let api_key = match extract_api_key(&request) {
                Some(key) => key,
                None => {
                    respond_json(
                        request,
                        StatusCode(401),
                        &ErrorResponse {
                            error: "missing X-Api-Key header".to_string(),
                        },
                    )?;
                    return Err(WalletError::Unauthorized("missing api key".to_string()));
                }
            };
            let session = match service.authenticate_api_key(&api_key) {
                Ok(s) => s,
                Err(err) => {
                    respond_json(
                        request,
                        StatusCode(401),
                        &ErrorResponse {
                            error: err.to_string(),
                        },
                    )?;
                    return Err(err);
                }
            };
            let mut body = String::new();
            request
                .as_reader()
                .read_to_string(&mut body)
                .map_err(|err| WalletError::Transport(err.to_string()))?;
            let instruction_req: InstructionRequest = serde_json::from_str(&body)
                .map_err(|err| WalletError::Input(format!("invalid instruction payload: {err}")))?;
            match service.queue_instruction(&session, instruction_req) {
                Ok(response) => respond_json(request, StatusCode(202), &response),
                Err(err) => {
                    let status = match &err {
                        WalletError::Input(_) => StatusCode(400),
                        WalletError::Unauthorized(_) => StatusCode(401),
                        WalletError::State(_) => StatusCode(500),
                        _ => StatusCode(500),
                    };
                    respond_json(
                        request,
                        status,
                        &ErrorResponse {
                            error: err.to_string(),
                        },
                    )?;
                    Err(err)
                }
            }
        }
        _ => respond_json(
            request,
            StatusCode(404),
            &ErrorResponse {
                error: "not found".to_string(),
            },
        ),
    }
}

fn respond_json<T: Serialize>(
    request: Request,
    status: StatusCode,
    payload: &T,
) -> Result<(), WalletError> {
    let header = Header::from_bytes(b"Content-Type", b"application/json").expect("static header");
    let body = serde_json::to_string(payload)
        .unwrap_or_else(|_| "{\"error\":\"serialization failure\"}".to_string());
    let response = Response::from_string(body)
        .with_status_code(status)
        .with_header(header);
    request
        .respond(response)
        .map_err(|err| WalletError::Transport(err.to_string()))
}

fn extract_api_key(request: &Request) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|header| {
            header
                .field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("x-api-key")
        })
        .map(|header| header.value.as_str().to_string())
}

#[derive(Debug)]
struct WalletService {
    secret_key: [u8; 32],
    address: H160,
    rpc_url: String,
    chain_id: u64,
    request_id: AtomicU64,
    send_lock: Mutex<()>,
    registry: Mutex<AccessRegistry>,
    user_counter: AtomicU64,
}

impl WalletService {
    fn new(secret_key: [u8; 32], address: H160, rpc_url: String, chain_id: u64) -> Self {
        // Keep lightweight global state behind mutexes so each request can borrow safely.
        Self {
            secret_key,
            address,
            rpc_url,
            chain_id,
            request_id: AtomicU64::new(1),
            send_lock: Mutex::new(()),
            registry: Mutex::new(AccessRegistry::default()),
            user_counter: AtomicU64::new(1),
        }
    }

    fn address(&self) -> H160 {
        self.address
    }

    fn fetch_balance(&self) -> Result<U256, WalletError> {
        let address = format!("0x{:x}", self.address);
        let result: String =
            self.rpc_call("eth_getBalance", serde_json::json!([address, "latest"]))?;
        parse_u256(&result)
            .map_err(|err| WalletError::Rpc(format!("unable to parse balance: {err}")))
    }

    fn fetch_gas_price(&self) -> Result<U256, WalletError> {
        let result: String = self.rpc_call("eth_gasPrice", serde_json::json!([]))?;
        parse_u256(&result)
            .map_err(|err| WalletError::Rpc(format!("unable to parse gas price: {err}")))
    }

    fn fetch_nonce(&self) -> Result<U256, WalletError> {
        let address = format!("0x{:x}", self.address);
        let result: String = self.rpc_call(
            "eth_getTransactionCount",
            serde_json::json!([address, "pending"]),
        )?;
        parse_u256(&result).map_err(|err| WalletError::Rpc(format!("unable to parse nonce: {err}")))
    }

    fn send_raw_transaction(&self, payload: &str) -> Result<H256, WalletError> {
        let result: String =
            self.rpc_call("eth_sendRawTransaction", serde_json::json!([payload]))?;
        let hash = parse_h256(&result)
            .map_err(|err| WalletError::Rpc(format!("invalid tx hash: {err}")))?;
        Ok(hash)
    }

    fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, WalletError> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let response = ureq::post(&self.rpc_url)
            .send_json(body)
            .map_err(|err| WalletError::Transport(err.to_string()))?;

        let response_body = response
            .into_body()
            .read_to_vec()
            .map_err(|err| WalletError::Transport(err.to_string()))?;
        let rpc_response: RpcResponse<T> = serde_json::from_slice(&response_body)
            .map_err(|err| WalletError::Transport(format!("invalid rpc response: {err}")))?;

        if let Some(error) = rpc_response.error {
            return Err(WalletError::Rpc(format!(
                "{} ({})",
                error.message, error.code
            )));
        }

        rpc_response
            .result
            .ok_or_else(|| WalletError::Rpc("missing result field".to_string()))
    }

    fn onboard_user(&self, request: OnboardRequest) -> Result<OnboardResponse, WalletError> {
        if request.name.trim().is_empty() {
            return Err(WalletError::Input("name is required".to_string()));
        }

        let max_withdraw = match request.max_withdraw_wei {
            Some(value) => parse_u256_dec_or_hex(&value)
                .map_err(|err| WalletError::Input(format!("invalid max_withdraw_wei: {err}")))?,
            None => U256::from_dec_str(DEFAULT_USER_CAP_WEI)
                .expect("DEFAULT_USER_CAP_WEI should be a valid number"),
        };

        let user_seq = self.user_counter.fetch_add(1, Ordering::Relaxed);
        let user_id = format!("usr-{:05}", user_seq);
        let api_key = self.derive_api_key(user_seq);

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| WalletError::State("access registry is poisoned".to_string()))?;

        // Persist both the API key lookup table and the user metadata.
        registry.api_index.insert(api_key.clone(), user_id.clone());
        registry.users.insert(
            user_id.clone(),
            UserAccount {
                id: user_id.clone(),
                name: request.name,
                strategy_tag: request.strategy_tag,
                max_withdraw_wei: max_withdraw,
                spent_wei: U256::zero(),
            },
        );

        Ok(OnboardResponse {
            user_id,
            api_key,
            deposit_address: format!("0x{:x}", self.address),
            max_withdraw_wei: max_withdraw.to_string(),
        })
    }

    fn authenticate_api_key(&self, api_key: &str) -> Result<UserSession, WalletError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| WalletError::State("access registry is poisoned".to_string()))?;
        let user_id = registry
            .api_index
            .get(api_key)
            .ok_or_else(|| WalletError::Unauthorized("invalid API key".to_string()))?;
        let account = registry
            .users
            .get(user_id)
            .ok_or_else(|| WalletError::Unauthorized("user not found".to_string()))?;

        Ok(UserSession {
            user_id: account.id.clone(),
        })
    }

    fn user_status(
        &self,
        session: &UserSession,
        requested_user_id: &str,
    ) -> Result<UserStatusResponse, WalletError> {
        if session.user_id != requested_user_id {
            return Err(WalletError::Unauthorized(
                "cannot query another user's status".to_string(),
            ));
        }
        let registry = self
            .registry
            .lock()
            .map_err(|_| WalletError::State("access registry is poisoned".to_string()))?;
        let account = registry
            .users
            .get(requested_user_id)
            .ok_or_else(|| WalletError::Unauthorized("user not found".to_string()))?;
        let available = account
            .max_withdraw_wei
            .checked_sub(account.spent_wei)
            .unwrap_or_else(U256::zero);

        Ok(UserStatusResponse {
            user_id: account.id.clone(),
            deposit_address: format!("0x{:x}", self.address),
            name: account.name.clone(),
            max_withdraw_wei: account.max_withdraw_wei.to_string(),
            spent_wei: account.spent_wei.to_string(),
            available_wei: available.to_string(),
            strategy_tag: account.strategy_tag.clone(),
        })
    }

    fn withdraw_for_user(
        &self,
        user: &UserSession,
        request: WithdrawRequest,
    ) -> Result<(WithdrawResponse, U256), WalletError> {
        // Parse and sanity-check the request before touching global state/balance.
        let to = parse_address(&request.to)?;
        let value = parse_u256_dec_or_hex(&request.value_wei)
            .map_err(|err| WalletError::Input(format!("invalid value_wei: {err}")))?;
        if value.is_zero() {
            return Err(WalletError::Input(
                "value must be greater than zero".to_string(),
            ));
        }

        self.enforce_withdrawal_cap(&user.user_id, &value)?;

        let gas_price = match request.gas_price_wei {
            Some(ref value) => parse_u256_dec_or_hex(value)
                .map_err(|err| WalletError::Input(format!("invalid gas_price_wei: {err}")))?,
            None => self.fetch_gas_price()?,
        };

        let gas_limit = U256::from(request.gas_limit.unwrap_or(DEFAULT_GAS_LIMIT));
        let data = parse_hex_bytes(request.data.as_deref().unwrap_or("0x"))
            .map_err(|err| WalletError::Input(format!("invalid data: {err}")))?;

        let balance = self.fetch_balance()?;
        let fee = gas_price
            .checked_mul(gas_limit)
            .ok_or_else(|| WalletError::Input("gas calculation overflow".to_string()))?;
        let total_cost = fee
            .checked_add(value)
            .ok_or_else(|| WalletError::Input("total cost overflow".to_string()))?;
        if total_cost > balance {
            return Err(WalletError::Input("insufficient balance".to_string()));
        }

        let _guard = self
            .send_lock
            .lock()
            .map_err(|_| WalletError::Signing("signing lock is poisoned".to_string()))?;

        let nonce = self.fetch_nonce()?;

        let tx = LegacyTransaction {
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
        };

        // Sign + broadcast while holding the send lock so nonces can't race.
        let (signed, signature_bytes, sighash_bytes) =
            sign_legacy(&tx, &self.secret_key, self.chain_id)?;
        let raw_hex = format!("0x{}", hex::encode(&signed));
        let signature_hex = format!("0x{}", hex::encode(signature_bytes));
        let sighash_hex = format!("0x{}", hex::encode(sighash_bytes));
        let tx_hash = self.send_raw_transaction(&raw_hex)?;

        Ok((
            WithdrawResponse {
                tx_hash: format!("0x{:x}", tx_hash),
                raw_transaction: raw_hex,
                nonce: format!("0x{:x}", nonce),
                total_cost_wei: total_cost.to_string(),
                signature: signature_hex,
                sighash: sighash_hex,
            },
            value,
        ))
    }

    fn enforce_withdrawal_cap(&self, user_id: &str, amount: &U256) -> Result<(), WalletError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| WalletError::State("access registry is poisoned".to_string()))?;
        let account = registry
            .users
            .get(user_id)
            .ok_or_else(|| WalletError::Unauthorized("user not found".to_string()))?;
        let projected = account
            .spent_wei
            .checked_add(*amount)
            .ok_or_else(|| WalletError::Input("allowance overflow".to_string()))?;
        if projected > account.max_withdraw_wei {
            return Err(WalletError::Unauthorized(
                "requested value exceeds allowance".to_string(),
            ));
        }
        Ok(())
    }

    fn record_withdrawal(&self, user_id: &str, amount: &U256) -> Result<(), WalletError> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| WalletError::State("access registry is poisoned".to_string()))?;
        let account = registry
            .users
            .get_mut(user_id)
            .ok_or_else(|| WalletError::Unauthorized("user not found".to_string()))?;
        account.spent_wei = account
            .spent_wei
            .checked_add(*amount)
            .ok_or_else(|| WalletError::Input("allowance overflow".to_string()))?;
        Ok(())
    }

    fn queue_instruction(
        &self,
        session: &UserSession,
        request: InstructionRequest,
    ) -> Result<InstructionResponse, WalletError> {
        let amount = parse_u256_dec_or_hex(&request.amount_wei)
            .map_err(|err| WalletError::Input(format!("invalid amount_wei: {err}")))?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| WalletError::State("access registry is poisoned".to_string()))?;
        if !registry.users.contains_key(&session.user_id) {
            return Err(WalletError::Unauthorized("user not found".to_string()));
        }
        registry.instruction_log.push(InstructionRecord {
            user_id: session.user_id.clone(),
            target_protocol: request.target_protocol.clone(),
            action: request.action.clone(),
            amount_wei: amount,
            note: request.note.clone(),
        });

        Ok(InstructionResponse {
            user_id: session.user_id.clone(),
            target_protocol: request.target_protocol,
            action: request.action,
            amount_wei: amount.to_string(),
            status: "queued".to_string(),
        })
    }

    fn derive_api_key(&self, user_seq: u64) -> String {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut hasher = Keccak256::new();
        hasher.update(&self.secret_key);
        hasher.update(user_seq.to_be_bytes());
        hasher.update(&salt);
        let digest = hasher.finalize();
        format!("apik_{}", hex::encode(digest))
    }
}

fn sign_legacy(
    tx: &LegacyTransaction,
    secret_key: &[u8; 32],
    chain_id: u64,
) -> Result<(Vec<u8>, [u8; 65], [u8; 32]), WalletError> {
    // Build EIP-155 legacy payload and capture the sighash for later verification.
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&tx.nonce);
    stream.append(&tx.gas_price);
    stream.append(&tx.gas_limit);
    stream.append(&tx.to);
    stream.append(&tx.value);
    stream.append(&tx.data);
    stream.append(&chain_id);
    stream.append(&0u8);
    stream.append(&0u8);
    let sighash_input = stream.out();

    let message_hash = Keccak256::digest(&sighash_input);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&message_hash);
    let message = Message::from_digest_slice(&hash_bytes)
        .map_err(|err| WalletError::Signing(format!("invalid message hash: {err}")))?;
    let secret = SecretKey::from_slice(secret_key)
        .map_err(|err| WalletError::Signing(format!("invalid secret key: {err}")))?;
    let secp = Secp256k1::new();
    let signature = secp.sign_ecdsa_recoverable(&message, &secret);
    let (rec_id, compact) = signature.serialize_compact();
    let r = U256::from_big_endian(&compact[..32]);
    let s = U256::from_big_endian(&compact[32..]);
    let v = U256::from(chain_id * 2 + 35 + rec_id.to_i32() as u64);

    let mut signature_bytes = [0u8; 65];
    signature_bytes[..64].copy_from_slice(&compact);
    signature_bytes[64] = 27 + rec_id.to_i32() as u8;

    // Encode final signed tx so it can be relayed over JSON-RPC.
    let mut encoded = rlp::RlpStream::new_list(9);
    encoded.append(&tx.nonce);
    encoded.append(&tx.gas_price);
    encoded.append(&tx.gas_limit);
    encoded.append(&tx.to);
    encoded.append(&tx.value);
    encoded.append(&tx.data);
    encoded.append(&v);
    encoded.append(&r);
    encoded.append(&s);

    Ok((encoded.out().to_vec(), signature_bytes, hash_bytes))
}

fn parse_u256(value: &str) -> Result<U256, String> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    U256::from_str_radix(without_prefix, 16).map_err(|err| err.to_string())
}

fn parse_u256_dec_or_hex(value: &str) -> Result<U256, String> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        U256::from_dec_str(trimmed).map_err(|err| err.to_string())
    }
}

fn parse_address(value: &str) -> Result<H160, WalletError> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if without_prefix.len() != 40 {
        return Err(WalletError::Input(
            "address must have 40 hex chars".to_string(),
        ));
    }
    let bytes = hex::decode(without_prefix)
        .map_err(|err| WalletError::Input(format!("invalid address hex: {err}")))?;
    Ok(H160::from_slice(&bytes))
}

fn parse_h256(value: &str) -> Result<H256, String> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if without_prefix.len() != 64 {
        return Err("hash must have 64 hex chars".to_string());
    }
    let bytes = hex::decode(without_prefix).map_err(|err| err.to_string())?;
    Ok(H256::from_slice(&bytes))
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(without_prefix).map_err(|err| err.to_string())
}

#[derive(Debug, Deserialize)]
struct WithdrawRequest {
    to: String,
    value_wei: String,
    #[serde(default)]
    gas_price_wei: Option<String>,
    #[serde(default)]
    gas_limit: Option<u64>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Serialize)]
struct AddressResponse {
    address: String,
}

#[derive(Debug, Serialize)]
struct BalanceResponse {
    address: String,
    balance_wei: String,
    balance_hex: String,
}

#[derive(Debug, Serialize)]
struct WithdrawResponse {
    tx_hash: String,
    raw_transaction: String,
    nonce: String,
    total_cost_wei: String,
    signature: String,
    sighash: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct OnboardRequest {
    name: String,
    #[serde(default)]
    strategy_tag: Option<String>,
    #[serde(default)]
    max_withdraw_wei: Option<String>,
}

#[derive(Debug, Serialize)]
struct OnboardResponse {
    user_id: String,
    api_key: String,
    deposit_address: String,
    max_withdraw_wei: String,
}

#[derive(Debug, Serialize)]
struct UserStatusResponse {
    user_id: String,
    deposit_address: String,
    name: String,
    max_withdraw_wei: String,
    spent_wei: String,
    available_wei: String,
    strategy_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InstructionRequest {
    target_protocol: String,
    action: String,
    amount_wei: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstructionResponse {
    user_id: String,
    target_protocol: String,
    action: String,
    amount_wei: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

struct LegacyTransaction {
    nonce: U256,
    gas_price: U256,
    gas_limit: U256,
    to: H160,
    value: U256,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct AccessRegistry {
    users: HashMap<String, UserAccount>,
    api_index: HashMap<String, String>,
    instruction_log: Vec<InstructionRecord>,
}

#[derive(Debug, Clone)]
struct UserAccount {
    id: String,
    name: String,
    strategy_tag: Option<String>,
    max_withdraw_wei: U256,
    spent_wei: U256,
}

#[derive(Debug, Clone)]
struct UserSession {
    user_id: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct InstructionRecord {
    user_id: String,
    target_protocol: String,
    action: String,
    amount_wei: U256,
    note: Option<String>,
}

#[derive(Debug, Error)]
enum WalletError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("input error: {0}")]
    Input(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("state error: {0}")]
    State(String),
}
