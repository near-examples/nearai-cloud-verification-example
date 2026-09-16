# NEAR AI Cloud Verification Example

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-22%2B-green.svg)](https://nodejs.org/)
[![NEAR AI Docs](https://img.shields.io/badge/NEAR_AI-Docs-blue.svg)](https://docs.near.ai/)

> 🚀 **Learn how to build secure, verifiable AI applications using NEAR AI Confidential Cloud**

This repository demonstrates how to interact with NEAR AI's Cloud platform, verify attestations, and ensure your AI workloads run in secure, trusted execution environments (TEEs).

## 🌟 What You'll Learn

- **🔒 Attestation Verification**: Get and verify model + gateway attestations from NEAR AI Cloud
- **🧾 Intel TDX Quotes**: Verify each quote against Intel's root of trust and check what it binds (signing key, nonce, gateway TLS key)
- **🛡️ Hardware Security**: Validate NVIDIA GPU attestations for secure execution (signed token, nonce freshness)
- **📌 TLS Pinning**: Send the prompt only over the TLS key the gateway TEE attested
- **🔐 Cryptographic Verification**: Verify signatures and hash integrity
- **🧭 Signature Kinds**: Understand who signed your response — the model TEE or the gateway TEE
- **⚡ End-to-End Workflow**: Complete pipeline from request to verified response

## 📋 Prerequisites

- **Node.js 22+** and **npm/pnpm**
- **NEAR AI Cloud API Key** ([Get yours here](https://cloud.near.ai/))
- Basic understanding of:
  - Trusted Execution Environments (TEEs)
  - Cryptographic signatures
  - Hash functions

## 🚀 Quick Start

### 1. Clone and Install

```bash
git clone https://github.com/near-examples/nearai-cloud-verification-example.git
cd nearai-cloud-verification-example
pnpm install  # or npm install
```

### 2. Configure Environment

Create a `.env` file with your NEAR AI Cloud API key: _(Get yours at https://cloud.near.ai)_

```bash
# .env
NEARAI_CLOUD_API_KEY=your_api_key_here
```

### 3. Run the Demo

```bash
pnpm start         # non-streaming chat request
pnpm start:stream  # streaming chat request (always signed by the gateway TEE)
```

The process exits with code `1` if any verification check fails. If any attestation check fails, the chat message is **not sent**.

## 🎯 What the Demo Does

The main demo (`app.js`) walks through a complete confidential AI workflow:

```
┌─────────────────────────────────────────────────────────────┐
│  🚀 NEAR AI Cloud Verification Demo                         │
├─────────────────────────────────────────────────────────────┤
│  1) Get Attestation Report (with a fresh random nonce)      │
│     ├─ Fetch model + gateway attestation from NEAR AI Cloud │
│     │  (asking the gateway to bind its TLS key)             │
│     ├─ Record the TLS key of the connection it came over    │
│     ├─ Extract model TEE and gateway TEE signing addresses  │
│     └─ Check the nonce is echoed back (replay protection)   │
│                                                             │
│  2) Verify Intel TDX Quotes (gateway + every model node)    │
│     ├─ Verify each quote with Intel collateral (no debug TD)│
│     ├─ Check the platform TCB status                        │
│     ├─ Check report_data binds the signing address + nonce  │
│     └─ Check the gateway's attested TLS key is the one this │
│        connection used (TLS terminates inside the TEE)      │
│                                                             │
│  3) Verify with NVIDIA                                      │
│     ├─ Send each GPU payload to NVIDIA's attestation service│
│     ├─ Verify the returned token against NVIDIA's keys      │
│     ├─ Validate the overall attestation verdict             │
│     └─ Check the NVIDIA token's eat_nonce matches our nonce │
│                                                             │
│     ⛔ Stop here if any check failed                        │
│                                                             │
│  4) Send & Verify Chat Message                              │
│     ├─ Send message over the pinned, attested TLS key       │
│     ├─ Fetch the signature for the returned chat id         │
│     ├─ Read `signature_kind` (provider_tee or gateway)      │
│     ├─ Verify model id + request/response hashes            │
│     └─ Recover the signer and match it to the right TEE key │
└─────────────────────────────────────────────────────────────┘
```

## 🧭 Signature Kinds

The signature endpoint returns a `signature_kind` field that tells you **which TEE signed** and what the signed `text` contains:

| `signature_kind` | Who signs | Signed `text` | When |
|------------------|-----------|---------------|------|
| `provider_tee` | The **model TEE** that served your request | `{model_id}:{request_hash}:{response_hash}` | Model signatures passed through by the gateway, and all direct completions endpoint responses |
| `gateway` | The **gateway TEE** (`cloud-api.near.ai`) | `{request_hash}:{response_hash}` | Whenever the gateway returns bytes the model TEE did not sign byte-for-byte (e.g. streams rewritten for OpenAI-compatible usage accounting) — it signs the exact bytes you receive. Non-streaming requests through `cloud-api.near.ai` can get this kind too |

The demo checks that `signature_kind` matches the format of `text` (a model TEE signature must include the requested model ID), then verifies the recovered signer against the matching address from the attestation report: `model_attestations[].signing_address` for `provider_tee`, or `gateway_attestation.signing_address` for `gateway`.

> Older signatures may omit `signature_kind`; the demo falls back to inferring it from the number of `:`-separated parts in `text`.

## 🏗️ Project Structure

```
nearai-cloud-verification-example/
├── app.js                          # 🎯 Main demo application
├── utils/                          # 🛠️ Utility modules
│   ├── api.js                      #    API interaction helpers
│   ├── model-attestation.js        #    Attestation + NVIDIA token processing
│   ├── tdx-attestation.js          #    Intel TDX quote + report_data checks
│   ├── tls.js                      #    HTTPS with TLS key capture and pinning
│   ├── send-and-verify-chat.js     #    Chat workflow
│   └── verification-helpers.js     #    Crypto verification
├── package.json                    # 📦 Dependencies
└── .env                            # 🔐 API key configuration
```

## 🔧 Core Components

### 🌐 API Integration (`utils/api.js`)

```javascript
import { getModelAttestation, getChatMessageSignature, getGpuAttestation } from './utils/api.js';
import { generateNonce } from './utils/verification-helpers.js';

// Get attestation for a model (nonce is optional but recommended)
const nonce = generateNonce();
// liveSpki: SHA-256 of the TLS public key the report was fetched over
const { report: attestation, liveSpki } = await getModelAttestation('zai-org/GLM-5.1-FP8', { nonce });

// Verify a GPU payload with NVIDIA
const nvidiaResult = await getGpuAttestation(attestation.model_attestations[0].nvidia_payload);

// Get signature for a chat completion (retries if the lookup lands on a different TEE node),
// refusing to connect unless the server presents the attested TLS key
const signature = await getChatMessageSignature(chatId, modelId, { pinnedSpki: liveSpki });
```

### 🛡️ Attestation Processing (`utils/model-attestation.js`)

```javascript
import {
  decodeNvidiaAttestation,
  summarizeGpuAttestation,
  extractSigningAddresses,
} from './utils/model-attestation.js';

// Pull out the model TEE + gateway TEE signing addresses
const { modelTee, gateway } = extractSigningAddresses(attestation);

// Verify NVIDIA's signed tokens, then check the verdict + nonce
const summary = summarizeGpuAttestation(await decodeNvidiaAttestation(nvidiaResult), nonce);
// summary.tokenVerified && summary.overallResult && summary.nonceMatch === true
```

### 🧾 Intel TDX Verification (`utils/tdx-attestation.js`)

```javascript
import { verifyTdxAttestation } from './utils/tdx-attestation.js';

// Verify the quote with Intel collateral and check its report_data:
//   [0..32]  = signing address (zero-padded), or
//              SHA256(signing address || TLS key fingerprint) when a TLS key is attested
//   [32..64] = our nonce
const tdx = await verifyTdxAttestation(attestation.gateway_attestation, nonce);
// tdx.passed, tdx.tcbStatus, tdx.advisoryIds, tdx.tlsBound

// For the gateway, also check the attested TLS key is the one we connected to
const tlsTerminatesInTee = attestation.gateway_attestation.tls_cert_fingerprint === liveSpki;
```

Platform TCB statuses `UpToDate`, `SWHardeningNeeded` and `OutOfDate` are accepted. `OutOfDate` means Intel has published advisories the host has not patched yet; the demo prints them.

### 🔐 Cryptographic Verification (`utils/verification-helpers.js`)

```javascript
import { verifySignature, compareHashes, sha256sum } from './utils/verification-helpers.js';

// Compare hashes against the signed text (handles both 2- and 3-part formats)
const hashResult = compareHashes(signature.text, requestHash, responseHash, modelId);

// Recover the signer and compare with the expected TEE address(es)
const signatureResult = await verifySignature(signature.text, signature.signature, expectedAddresses);

// Generate SHA-256 hash of the exact bytes sent/received
const hash = sha256sum(data);
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NEARAI_CLOUD_API_KEY` | Your NEAR AI Cloud API key | ✅ Yes |
| `MODEL_NAME` | TEE-hosted model to test (default `zai-org/GLM-5.1-FP8`) | No |
| `STREAM` | Set to `true` to stream the chat response (`signature_kind` becomes `gateway`) | No |

### Model Configuration

Only **TEE-hosted** models support attestation and signatures. Third-party models (OpenAI, Anthropic, Gemini, …) are proxied through the gateway and are not verifiable. See the current list at https://docs.near.ai/cloud/models or `GET https://cloud-api.near.ai/v1/models`.

```bash
MODEL_NAME=Qwen/Qwen3.5-122B-A10B pnpm start
MODEL_NAME=deepseek-ai/DeepSeek-V4-Flash pnpm start
```

### 🔒 Security Guarantees

When you see ✅ for all checks, you have cryptographic proof that:

- **🏗️ Trusted Hardware**: The gateway and every model node run in genuine, non-debug Intel TDX TEEs, and the model's GPUs pass NVIDIA attestation, all attested freshly (nonce-bound)
- **🔑 Attested Keys**: The signing addresses you check responses against are bound into hardware-signed quotes, not just reported by the server
- **🔒 Encrypted to the TEE**: Your prompt travels over a TLS key the gateway TEE attested, so TLS terminates inside it
- **🔐 Data Integrity**: Request and response haven't been tampered with
- **✍️ Authenticity**: Response was signed by the attested model TEE or by the attested gateway TEE, as reported by `signature_kind`

What this demo still does **not** check:

- Which software runs in the TEEs. It does not compare the Docker compose manifest with `mr_config`, replay the event log, or check Sigstore provenance, so you still trust NEAR AI's deployment.
- That the GPU evidence comes from the same machine as a TDX quote. The two are tied together only by the shared nonce.

For those, see the [NEAR AI Cloud Verifier](https://github.com/nearai/nearai-cloud-verifier).

## 🚨 Troubleshooting

### Common Issues

**❌ API Key Not Found**
```bash
Error: 401 Unauthorized
💡 Tip: Make sure your NEARAI_CLOUD_API_KEY is set in the .env file
```

**❌ Model Not Available**
```bash
Error: 404 Not Found
💡 Tip: The model name might have a typo or might not be a TEE-hosted model
```

**❌ Signature Not Found**
```bash
Error: Signature request failed: 404 ... Chat id not found or expired
💡 Tip: A model can be served by several TEE nodes; the demo retries a few times automatically
```

**❌ Gateway TLS Key Not Bound**
```bash
❌ This connection's TLS key is the attested gateway key (TLS ends inside the TEE)
💡 Tip: The gateway did not return a tls_cert_fingerprint, or a proxy (corporate
   TLS inspection, a VPN) presented a different certificate. The chat is not sent.
```

**❌ Network Issues**
```bash
Error: fetch failed
💡 Tip: Check your internet connection and API endpoints
```

## 🔗 API Endpoints

The demo interacts with these NEAR AI Cloud endpoints:

- **Attestation**: `GET https://cloud-api.near.ai/v1/attestation/report?model={model}&signing_algo=ecdsa&nonce={nonce}&include_tls_fingerprint=true`
- **Chat Completions**: `POST https://cloud-api.near.ai/v1/chat/completions`
- **Signatures**: `GET https://cloud-api.near.ai/v1/signature/{chatId}?model={model}&signing_algo=ecdsa`

And external verification:

- **Intel Collateral**: `https://api.trustedservices.intel.com` (TCB info, QE identity, CRLs)
- **NVIDIA Attestation**: `POST https://nras.attestation.nvidia.com/v3/attest/gpu`
- **NVIDIA Token Keys**: `GET https://nras.attestation.nvidia.com/.well-known/jwks.json`

## 📚 Learn More

- **[NEAR AI Cloud Documentation](https://docs.near.ai)**
- **[Model Verification](https://docs.near.ai/cloud/verification/model)** / **[Gateway Verification](https://docs.near.ai/cloud/verification/gateway)** / **[Chat Message Verification](https://docs.near.ai/cloud/verification/chat)**
- **[NEAR AI Cloud Verifier](https://github.com/nearai/nearai-cloud-verifier)** (full Python/TypeScript verifier)
- **[NVIDIA Confidential Computing](https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/)**
- **[NVIDIA Attestation Service](https://docs.api.nvidia.com/attestation/reference/attestationinfo)**
- **[Trusted Execution Environments](https://en.wikipedia.org/wiki/Trusted_execution_environment)**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
