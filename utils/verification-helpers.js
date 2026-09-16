import { ethers } from "ethers";
import { createHash, randomBytes } from "crypto";

/**
 * Generate a fresh attestation nonce: 32 random bytes as a 64-char hex string.
 * Sending a nonce with the attestation request ensures freshness and prevents replay.
 * @returns {string}
 */
function generateNonce() {
  return randomBytes(32).toString("hex");
}

/**
 * SHA-256 hex digest of a UTF-8 string
 * @param {string} data
 * @returns {string}
 */
function sha256sum(data) {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Recover the signer of an ECDSA (EIP-191 personal_sign) signature and compare it
 * against one or more expected TEE signing addresses.
 * @param {string} message - The signed `text`
 * @param {string} signature - The hex signature
 * @param {string|string[]} expectedAddresses
 */
async function verifySignature(message, signature, expectedAddresses) {
  const addressArray = Array.isArray(expectedAddresses)
    ? expectedAddresses
    : [expectedAddresses];

  try {
    const recoveredAddress = ethers.verifyMessage(message, signature);

    const isValid = addressArray.some(
      (addr) => recoveredAddress.toLowerCase() === String(addr).toLowerCase()
    );

    return {
      valid: isValid,
      expectedAddresses: addressArray,
      recoveredAddress,
      message,
    };
  } catch (error) {
    return {
      valid: false,
      error: error.message,
      expectedAddresses: addressArray,
      recoveredAddress: null,
      message,
    };
  }
}

/**
 * Validate request/response hashes against the signed `text` payload.
 *
 * The signed text has one of two formats, depending on `signature_kind`:
 *   provider_tee: "{model_id}:{request_hash}:{response_hash}"  (signed inside the model TEE)
 *   gateway:      "{request_hash}:{response_hash}"             (signed inside the gateway TEE)
 *
 * @param {string} signatureText - The `text` field from the signature response
 * @param {string} expectedRequestHash - sha256 of the exact request body sent
 * @param {string} expectedResponseHash - sha256 of the exact response body received
 * @param {string} [expectedModelId] - If provided and the text carries a model id, it must match
 * @returns {Object} Validation result with details
 */
function compareHashes(
  signatureText,
  expectedRequestHash,
  expectedResponseHash,
  expectedModelId
) {
  try {
    const parts = signatureText.split(":");

    if (parts.length !== 2 && parts.length !== 3) {
      return {
        valid: false,
        error: `Expected 2 or 3 ':'-separated parts in signed text, got ${parts.length}`,
        signatureText,
        expectedRequestHash,
        expectedResponseHash,
      };
    }

    const hasModelId = parts.length === 3;
    const signedModelId = hasModelId ? parts[0] : null;
    const signedRequestHash = parts[hasModelId ? 1 : 0];
    const signedResponseHash = parts[hasModelId ? 2 : 1];

    const requestHashMatch = signedRequestHash === expectedRequestHash;
    const responseHashMatch = signedResponseHash === expectedResponseHash;
    // null when the signed text has no model id (gateway signature)
    const modelIdMatch =
      hasModelId && expectedModelId ? signedModelId === expectedModelId : null;

    return {
      valid: requestHashMatch && responseHashMatch && modelIdMatch !== false,
      requestHashMatch,
      responseHashMatch,
      modelIdMatch,
      signedModelId,
      signedRequestHash,
      signedResponseHash,
      expectedModelId: expectedModelId ?? null,
      expectedRequestHash,
      expectedResponseHash,
      signatureText,
    };
  } catch (error) {
    return {
      valid: false,
      error: `Error validating hashes: ${error.message}`,
      signatureText,
      expectedRequestHash,
      expectedResponseHash,
    };
  }
}

export { compareHashes, verifySignature, sha256sum, generateNonce };
