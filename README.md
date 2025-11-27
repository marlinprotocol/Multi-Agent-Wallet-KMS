# Multi-Agent Yield Vault (Signing Server)

TEE-native Sepolia wallet tailored for multi-agent (ERC-8004-inspired) DeFi strategies. A central maintainer funds the enclave-controlled wallet once, then any specialized AI/automation agent onboards to obtain a scoped API key for initiating withdrawals or queuing strategy instructions. The enclave keeps custody, enforces policy, and signs only after verifying the requesting agent’s allowance—every signature and API key is produced from a KMS-derived key powered by Oyster’s contract KMS service.

## Why this exists

Coordinating a fleet of ERC-8004-style AI agents is hard when each bot needs direct wallet access. This vault keeps the contract-approved private key solely inside a Trusted Execution Environment (TEE) while presenting API keys to agents. The maintainer can:

- Deposit once from a personal wallet and let agents rebalance capital safely.
- Grant deterministic, non-exportable API keys tied to the enclave’s contract KMS secret.
- Log every instruction/withdrawal request per agent while enforcing spend caps.

## High-level architecture

1. **TEE enclave container** – runs `signing-server` binary, loads `.env`, derives the secp256k1 key from `http://127.0.0.1:1100/derive/secp256k1?path=<CONTRACT_KMS_PATH>`, and starts an HTTP server.
2. **Contract KMS** – Oyster contract-based derive service approves the enclave image and issues the same wallet key across upgrades.
3. **Sepolia RPC** – HTTPS endpoint (Alchemy/Infura/etc.) used for balance, nonce, gas price queries, and broadcasting signed transactions.
4. **Access registry** – in-memory (and sealable if extended) structure inside the enclave maintaining user profiles, API keys, spend caps, cumulative withdrawals, and a log of DeFi strategy instructions.

## Features

- **TEE-only private key** derived via contract KMS; no agent ever sees raw key material.
- **Onboarding API** lets each AI/automation agent mint a scoped ID + API key with a custom spend cap.
- **Access control & throttling** enforce per-agent allowances before any tx gets signed.
- **Deterministic API keys** use the enclave-only KMS secret plus per-agent salt so keys are non-invertible and revocable.
- **Strategy instruction queue** lets specialized agents (Aave, DEX, hedging, etc.) submit playbooks for later execution.
- **Ledger awareness** exposes on-chain balance/nonce while tracking agent-level spend history to inform decisioning.
- **Simple HTTP interface** works with `curl`, Postman, or autonomous bots coordinating over ERC-8004 flows.

## Example multi-agent flow

1. **Fund once** – the maintainer seeds the enclave-owned wallet from a personal Sepolia account.
2. **Specialize agents** – each AI agent (Aave rebalancer, DEX arb, hedging bot, etc.) runs `POST /users` to receive an ID + API key tied to the enclave.
3. **Queue strategies** – when an opportunity is detected (e.g., move an Aave position to stable collateral), the agent submits `/instructions/strategy`:

    ```bash
    curl -X POST http://localhost:8080/instructions/strategy \
      -H 'Content-Type: application/json' \
      -H 'X-Api-Key: <api_key>' \
      -d '{"target_protocol":"aave-v3","action":"roll-to-stable","amount_wei":"0x1bc16d674ec80000","note":"raise LTV to 60%"}'
    ```

4. **Execute trades** – the same or another agent can call `/withdraw` to execute a transaction directly, subject to their allowance. The enclave signs and broadcasts only after verifying caps.

## Configuration

Following Oyster’s guidance on init params, split configuration from secrets:

1. **Create `config.env`** (attested, not encrypted) using `.env.config.example` as a template:

  ```env
  CONTRACT_KMS_PATH=sepolia-wallet
  WALLET_LISTEN_ADDR=0.0.0.0:8080
  ```

2. **Create `secrets.env`** (encrypted, excluded from attestation) using `.env.secrets.example` as a template:

  ```env
  SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<your-api-key>
  ```

3. For local development, you may still copy `.env.example` to `.env`; `dotenvy` loads it automatically when present.

When deploying/simulating, pass both files via separate `--init-params` flags so they land inside `/init-params/config.env` (attested plaintext) and `/init-params/secrets.env` (encrypted, not attested).

## Building & running locally

1. Copy the provided templates:

  ```bash
  cp .env.config.example config.env
  cp .env.secrets.example secrets.env
  ```

2. Edit `config.env` to reflect attested-but-not-secret settings (e.g., `CONTRACT_KMS_PATH`, `WALLET_LISTEN_ADDR`).
3. Edit `secrets.env` with sensitive values such as `SEPOLIA_RPC_URL`; keep this file encrypted or excluded from version control.

### Simulating the Oyster environment locally

Before deploying to an actual TEE you can exercise the full flow inside `oyster-cvm simulate`:

1. Edit `src/main.rs` and change `KMS_ENDPOINT_PREFIX` so it hits port `1100` instead of `1101`. The simulator exposes a mock derive server on 1100.
2. Provide both `config.env` and `secrets.env` locally (they will be copied into `/init-params/`).
3. Build and push the Docker image the simulator will pull:

  ```bash
  sudo docker build -t ayushranjan123/signing-server:latest --push .
  ```

4. Launch the simulator:

  ```bash
  oyster-cvm simulate \
    --docker-compose docker-compose.yml \
    --init-params "config.env:1:0:file:./config.env" \
    --init-params "secrets.env:0:1:file:./secrets.env" \
    --expose-ports 8080
  ```

Here `config.env` is attested but unencrypted, while `secrets.env` is encrypted and omitted from attestation. The wallet binary boots in the simulator, exposed on port 8080, and mounts both files as environment sources via Docker Compose.

### Deploying to Oyster

Make sure `KMS_ENDPOINT_PREFIX` in `src/main.rs` hits port `1101`.

1. Build and push the enclave image that Oyster will fetch:

  ```bash
  sudo docker build -t ayushranjan123/signing-server:latest --push .
  ```

2. Deploy the contract KMS helper (replace `<key>` with your wallet private key):

  ```bash
  oyster-cvm kms-contract deploy --wallet-private-key <key>
  ```

3. Compute the image ID for attestation. Supply your contract address and reference both init-param files. Example for amd64:

  ```bash
  oyster-cvm compute-image-id \
    --contract-address <address> \
    --chain-id 42161 \
    --docker-compose docker-compose.yml \
    --init-params "config.env:1:0:file:./config.env" \
    --init-params "secrets.env:0:1:file:./secrets.env" \
    --arch amd64
  ```

  For arm64 omit `--arch amd64`.

4. Approve the computed image ID so Oyster can derive the wallet key for this image:

  ```bash
  oyster-cvm kms-contract approve \
    --wallet-private-key <key> \
    --image-id <image_id> \
    --contract-address <address>
  ```

5. Finally deploy the enclave. 

  ```bash
  oyster-cvm deploy \
    --wallet-private-key <key> \
    --contract-address <address> \
    --chain-id 42161 \
    --duration-in-minutes 30 \
    --docker-compose docker-compose.yml \
    --init-params "config.env:1:0:file:./config.env" \
    --init-params "secrets.env:0:1:file:./secrets.env" \
    --arch amd64
  ```

  Remove `--arch amd64` for arm64 deployments.

This workflow keeps configuration within attestation evidence while secrets remain encrypted in transit and excluded from the quote.

## API reference

All responses are JSON. Endpoints marked 🔐 require an `X-Api-Key` header obtained during onboarding.

### `GET /address`
Returns the enclave-owned Sepolia address.
```bash
curl http://localhost:8080/address
```

### `GET /balance`
Reports current on-chain balance in Wei and hex.
```bash
curl http://localhost:8080/balance
```

### `POST /users`
Onboard a new agent/automation desk. 

```bash
curl -X POST http://localhost:8080/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"Aave Momentum","strategy_tag":"aave-rebalancer","max_withdraw_wei":"0xde0b6b3a7640000"}'
```

Body:

```json
{
  "name": "Aave Momentum",
  "strategy_tag": "aave-rebalancer",   // optional, helps label the agent
  "max_withdraw_wei": "0xde0b6b3a7640000"   // optional, defaults to 1 ETH
}
```

Response (`201 Created`):

```json
{
  "user_id": "usr-00001",
  "api_key": "a3c4...",
  "deposit_address": "0xf63a...",
  "max_withdraw_wei": "1000000000000000000"
}
```

> API keys are minted by hashing the enclave’s contract-KMS secret with a per-user salt. They are unique per onboarding flow and cannot be inverted to reveal the underlying wallet key.
>
> Provide `strategy_tag` (e.g., `aave-rebalancer`, `dex-arb`) to make it easier to audit which agent issued later instructions; it is echoed back via `/users/{id}/status`.

### `GET /users/{user_id}/status`
Header: `X-Api-Key: <api_key>`.
Returns spend history, remaining allowance, and deposit address for the caller.

### `POST /withdraw`

Header: `X-Api-Key`. Example request:

```bash
curl -X POST http://localhost:8080/withdraw \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: <api_key>' \
  -d '{"to":"0xRecipient...","value_wei":"1000000000000000"}'
```

Body mirrors standard Ethereum tx fields:

```json
{
  "to": "0xRecipient...",
  "value_wei": "50000000000000000",
  "gas_price_wei": null,
  "gas_limit": 25000,
  "data": "0x"
}
```

The enclave ensures `value_wei` is within the caller’s cap, signs the transaction with the TEE key, submits via `eth_sendRawTransaction`, and returns tx hash, raw RLP, nonce, and total cost.

Response (`200 OK`):

```json
{
  "tx_hash": "0x...",
  "raw_transaction": "0x...",
  "nonce": "0x12",
  "total_cost_wei": "123456789",
  "signature": "0x<65-byte-recoverable-signature>",
  "sighash": "0x<32-byte-hash-of-signed-payload>"
}
```

### `POST /instructions/strategy`

Header: `X-Api-Key`. Allows a strategist to queue a DeFi action for later automated execution.

```bash
curl -X POST http://localhost:8080/instructions/strategy \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: <api_key>' \
  -d '{"target_protocol":"aave-v3","action":"roll-to-stable","amount_wei":"0x1bc16d674ec80000","note":"raise LTV to 60%"}'
```

```json
{
  "target_protocol": "aave-v3",
  "action": "roll-to-stable",
  "amount_wei": "0x1bc16d674ec80000",
  "note": "raise LTV to 60%"
}
```

Response (`202 Accepted`) confirms the instruction was logged.

#### Verifying the signer

1. Call `POST /withdraw` and copy the `signature` and `sighash` fields from the response.
2. Fetch the expected public key directly from contract KMS:

  ```bash
  oyster-cvm kms-derive --contract-address <address> --chain-id 42161 --path signing-server --key-type secp256k1/public
  ```

3. Run the verifier helper (third argument optional but recommended). Passing the KMS public key asserts both values match:

  ```bash
  cargo run --bin verifier -- <signature_hex> <sighash_hex> <expected_pubkey_hex>
  ```

`signature_hex` is the 65-byte recoverable signature returned by `/withdraw`, `sighash_hex` is the 32-byte hash of the signed payload, and `expected_pubkey_hex` is the 64-byte uncompressed pubkey (without 0x04 prefix) from KMS. The command prints the recovered public key and exits non-zero if it differs from the expected value.

## Operational workflow

1. **Deploy & attest** – build Docker image, compute Oyster image ID, and register/approve it via the contract KMS flow.
2. **Start the enclave** – `cargo run` locally or `oyster-cvm deploy …` in production.
3. **Onboard agents** – each specialized bot calls `POST /users` to receive an API key tied to the enclave and funds the shared `deposit_address` as needed.
4. **Monitor caps** – agents hit `/users/{id}/status` to check allowance headroom before issuing trades.
5. **Submit instructions** – bots enqueue strategy adjustments through `/instructions/strategy`; operators may extend the server to auto-act on these logs.
6. **Withdraw / rebalance** – `/withdraw` executes transactions directly, with the enclave enforcing per-agent allowances before touching chain state.

## Extending the project

- Implement automatic execution of queued strategy instructions (e.g., integrate with on-chain protocols or DEX routers).

