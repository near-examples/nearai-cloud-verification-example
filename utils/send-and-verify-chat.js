#!/usr/bin/env node
import { sendChatMessageRequest, getChatMessageSignature } from "./api.js";
import { sha256sum, compareHashes, verifySignature, splitSignedText } from "./verification-helpers.js";

/**
 * Work out which key signed the response.
 * Newer signatures carry `signature_kind`; older ones can be inferred from the
 * shape of `text` (3 parts = model TEE, 2 parts = gateway).
 * @returns {"provider_tee"|"gateway"}
 */
function resolveSignatureKind(signature) {
  if (signature.signature_kind === "provider_tee" || signature.signature_kind === "gateway") {
    return signature.signature_kind;
  }
  return splitSignedText(signature.text).length === 3 ? "provider_tee" : "gateway";
}

/**
 * Send a chat message and verify the returned hashes + signature.
 *
 * @param {string} chatContent - User message
 * @param {string} modelId - Model to query
 * @param {{modelTee: string[], gateway: string[]}|string[]} expectedAddresses
 *   Signing addresses from the attestation report. A plain array is treated as model TEE addresses.
 * @param {{stream?: boolean, pinnedSpki?: string|null}} [options]
 *   stream: whether to stream the response. The gateway signs (`gateway`) whenever it
 *           returns bytes the model TEE did not sign byte-for-byte (e.g. rewritten
 *           streams); otherwise the model TEE's signature is passed through (`provider_tee`).
 *   pinnedSpki: attested gateway TLS key. Requests are refused unless the server presents it.
 */
async function sendAndVerifyChatMessage(chatContent, modelId, expectedAddresses, options = {}) {
  const { stream = false, pinnedSpki = null } = options;

  const addresses = Array.isArray(expectedAddresses)
    ? { modelTee: expectedAddresses, gateway: [] }
    : { modelTee: [], gateway: [], ...expectedAddresses };

  // The exact string sent over the wire is what gets hashed and signed
  const requestBody = JSON.stringify({
    messages: [{ content: chatContent, role: "user" }],
    stream,
    model: modelId,
  });

  try {
    // Step 1: Send chat message request
    const response = await sendChatMessageRequest(requestBody, { pinnedSpki });
    if (!response.chatId) {
      throw new Error("Could not extract chat completion id from response");
    }

    // Step 2: Hash the exact request and response bytes
    const requestHash = sha256sum(requestBody);
    const responseHash = sha256sum(response.responseText);

    // Step 3: Fetch the signature for this chat id
    const signature = await getChatMessageSignature(response.chatId, modelId, { pinnedSpki });
    const signatureKind = resolveSignatureKind(signature);

    // Step 4: Validate hashes (and model id, when the model TEE signed)
    const hashValidation = compareHashes(signature.text, requestHash, responseHash, modelId);

    // The declared kind must match the signed payload, so a server-supplied kind
    // can't route a model-less payload to the model TEE check or vice versa
    const signedPartCount = splitSignedText(signature.text).length;
    const signatureKindMatch = signedPartCount === (signatureKind === "provider_tee" ? 3 : 2);
    // A model TEE signature must commit to the model id we asked for
    if (signatureKind === "provider_tee" && hashValidation.valid && hashValidation.modelIdMatch !== true) {
      hashValidation.valid = false;
      hashValidation.error = "Model TEE signature must include the requested model id";
    }

    // Step 5: Verify the signature against the key that is supposed to have signed
    const expectedForKind =
      signatureKind === "gateway" ? addresses.gateway : addresses.modelTee;
    const signatureValidation = await verifySignature(
      signature.text,
      signature.signature,
      expectedForKind
    );

    return {
      chatContent,
      modelId,
      stream,
      requestBody,
      response,
      requestHash,
      responseHash,
      signature,
      signatureKind,
      signatureKindMatch,
      hashValidation,
      signatureValidation,
    };
  } catch (error) {
    throw new Error(`Error sending and verifying chat message: ${error.message}`);
  }
}

export { sendAndVerifyChatMessage, resolveSignatureKind };
