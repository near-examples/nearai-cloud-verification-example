#!/usr/bin/env node
import dotenv from "dotenv";

dotenv.config({ quiet: true });

export const NEARAI_BASE_URL =
  process.env.NEARAI_CLOUD_BASE_URL || "https://cloud-api.near.ai";
export const NVIDIA_NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu";

function authHeaders() {
  return { Authorization: `Bearer ${process.env.NEARAI_CLOUD_API_KEY}` };
}

/**
 * Build a descriptive error from a failed fetch Response (includes body snippet)
 * @param {Response} response
 * @param {string} context
 * @returns {Promise<Error>}
 */
async function httpError(response, context) {
  let detail = "";
  try {
    detail = (await response.text()).slice(0, 300);
  } catch {
    // ignore body read errors
  }
  return new Error(
    `${context}: ${response.status} ${response.statusText}${detail ? ` - ${detail}` : ""}`
  );
}

/**
 * Extract the chat completion ID from a response body.
 * Handles both streaming (SSE `data:` lines) and non-streaming (plain JSON) bodies.
 * @param {string} responseText - The raw response text
 * @returns {string|null} The chat completion ID or null if not found
 */
function extractChatCompletionId(responseText) {
  try {
    const trimmed = responseText.trimStart();
    if (trimmed.startsWith("{")) {
      return JSON.parse(trimmed).id || null;
    }
    const firstDataLine = responseText
      .split("\n")
      .find((line) => line.startsWith("data: {"));
    if (firstDataLine) {
      const json = JSON.parse(firstDataLine.substring(6));
      return json.id || null;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Send a Chat Message Request to NEAR AI Confidential Cloud
 * @param {string} requestBody - The exact JSON request body string to send (this exact string is hashed)
 * @returns {Promise<{response: Response, responseText: string, chatId: string|null}>}
 */
async function sendChatMessageRequest(requestBody) {
  const response = await fetch(`${NEARAI_BASE_URL}/v1/chat/completions`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "Content-Type": "application/json",
      ...authHeaders(),
    },
    body: requestBody,
  });

  if (!response.ok) {
    throw await httpError(response, "Chat completion request failed");
  }

  // Read the exact bytes returned; this exact string is what gets hashed and signed
  const responseText = await response.text();
  const chatId = extractChatCompletionId(responseText);

  return { response, responseText, chatId };
}

/**
 * Get signature for a chat message from NEAR AI Confidential Cloud.
 *
 * A model can be served by multiple TEE nodes; the signature is cached on the node
 * that served the completion, so a lookup may transiently 404 if it lands on a
 * different node. We retry a few times to handle that.
 *
 * @param {string} chatId - The chat completion ID
 * @param {string} modelId - The model ID
 * @param {{signingAlgo?: string, retries?: number, retryDelayMs?: number}} [options]
 * @returns {Promise<{text: string, signature: string, signing_address: string, signing_algo: string, signature_kind?: string}>}
 */
async function getChatMessageSignature(chatId, modelId, options = {}) {
  const { signingAlgo = "ecdsa", retries = 5, retryDelayMs = 1000 } = options;
  const url =
    `${NEARAI_BASE_URL}/v1/signature/${encodeURIComponent(chatId)}` +
    `?model=${encodeURIComponent(modelId)}&signing_algo=${encodeURIComponent(signingAlgo)}`;

  let lastError;
  for (let attempt = 1; attempt <= retries; attempt++) {
    const response = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json", ...authHeaders() },
    });

    if (response.ok) {
      return await response.json();
    }

    lastError = await httpError(response, "Signature request failed");
    if (response.status !== 404 || attempt === retries) break;
    await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
  }
  throw lastError;
}

/**
 * Get an attestation report from NEAR AI Cloud.
 *
 * With a model name, the report contains `model_attestations` (one per TEE node
 * serving the model) plus `gateway_attestation`. Without a model name, only the
 * gateway attestation is returned.
 *
 * @param {string|null} modelName - Model to attest, or null for gateway-only
 * @param {{nonce?: string, signingAlgo?: string}} [options]
 *   nonce: 64-char hex string (32 random bytes). Echoed back in `request_nonce`
 *          and bound into the NVIDIA payload / TDX report_data to prevent replay.
 * @returns {Promise<Object>} Attestation report
 */
async function getModelAttestation(modelName, options = {}) {
  const { nonce, signingAlgo = "ecdsa" } = options;
  const params = new URLSearchParams({ signing_algo: signingAlgo });
  if (modelName) params.set("model", modelName);
  if (nonce) params.set("nonce", nonce);

  const response = await fetch(
    `${NEARAI_BASE_URL}/v1/attestation/report?${params.toString()}`,
    { headers: { accept: "application/json", ...authHeaders() } }
  );

  if (!response.ok) {
    throw await httpError(response, "Attestation request failed");
  }

  return await response.json();
}

/**
 * Verify NVIDIA GPU attestation using NVIDIA's Remote Attestation Service (NRAS)
 * @param {string|Object} nvidiaPayload - The `nvidia_payload` from the attestation report (JSON string or object)
 * @returns {Promise<Array>} NRAS response: [["JWT", token], {"GPU-0": token, ...}]
 */
async function getGpuAttestation(nvidiaPayload) {
  const body =
    typeof nvidiaPayload === "string" ? nvidiaPayload : JSON.stringify(nvidiaPayload);

  const response = await fetch(NVIDIA_NRAS_URL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body,
  });

  if (!response.ok) {
    throw await httpError(response, "GPU attestation verification failed");
  }
  return await response.json();
}

export {
  sendChatMessageRequest,
  extractChatCompletionId,
  getChatMessageSignature,
  getModelAttestation,
  getGpuAttestation,
};
