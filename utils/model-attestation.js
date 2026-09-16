#!/usr/bin/env node
import { decodeJwt } from "jose";

/**
 * Decode NVIDIA NRAS attestation response format
 * @param {Array} nvidiaResponse - Array response from NVIDIA: [["JWT", token], {"GPU-0": token, ...}]
 * @returns {Object} Decoded claims keyed by "JWT" (overall) and "GPU-n" (per GPU)
 */
export function decodeNvidiaAttestation(nvidiaResponse) {
  const result = {};

  if (!Array.isArray(nvidiaResponse)) {
    throw new Error("Expected array response from NVIDIA attestation service");
  }

  const decodeToken = (key, token) => {
    if (typeof token === "string" && token.includes(".")) {
      try {
        result[key] = decodeJwt(token);
      } catch (error) {
        console.warn(`Failed to decode ${key} token: ${error.message}`);
        result[key] = { error: error.message };
      }
    }
  };

  nvidiaResponse.forEach((item) => {
    if (Array.isArray(item)) {
      // ["JWT", "token_string"]
      if (item.length === 2) decodeToken(item[0], item[1]);
    } else if (typeof item === "object" && item !== null) {
      // {"GPU-0": "token_string"}
      Object.entries(item).forEach(([key, token]) => decodeToken(key, token));
    }
  });

  return result;
}

/**
 * Summarize a decoded NVIDIA attestation into the checks we care about.
 * @param {Object} decoded - Output of decodeNvidiaAttestation
 * @param {string} [expectedNonce] - The nonce sent with the attestation request
 * @returns {{overallResult: boolean, eatNonce: string|null, nonceMatch: boolean|null, gpus: Array}}
 */
export function summarizeGpuAttestation(decoded, expectedNonce) {
  const overall = decoded.JWT || {};
  const eatNonce = overall.eat_nonce ?? null;
  const nonceMatch =
    expectedNonce && eatNonce
      ? eatNonce.toLowerCase() === expectedNonce.toLowerCase()
      : null;

  const gpus = Object.entries(decoded)
    .filter(([key]) => key.startsWith("GPU-"))
    .map(([key, claims]) => ({
      key,
      hwmodel: claims.hwmodel ?? null,
      driverVersion: claims["x-nvidia-gpu-driver-version"] ?? null,
      vbiosVersion: claims["x-nvidia-gpu-vbios-version"] ?? null,
      secureBoot: claims.secboot ?? null,
      debugStatus: claims.dbgstat ?? null,
      nonceMatch: claims["x-nvidia-gpu-attestation-report-nonce-match"] ?? null,
      measurementResult: claims.measres ?? null,
    }));

  return {
    overallResult: overall["x-nvidia-overall-att-result"] === true,
    eatNonce,
    nonceMatch,
    gpus,
  };
}

/**
 * Pull the signing addresses out of an attestation report.
 *
 * - `modelTee`: one address per TEE node serving the model (signs `provider_tee` chat signatures)
 * - `gateway`:  the cloud-api gateway TEE address (signs `gateway` chat signatures)
 *
 * @param {Object} attestationReport - Response from /v1/attestation/report
 * @returns {{modelTee: string[], gateway: string[]}}
 */
export function extractSigningAddresses(attestationReport) {
  const modelTee = [];
  for (const attestation of attestationReport.model_attestations ?? []) {
    const addr = attestation.signing_address;
    if (addr && !modelTee.includes(addr)) modelTee.push(addr);
  }

  const gateway = [];
  const gatewayAddr = attestationReport.gateway_attestation?.signing_address;
  if (gatewayAddr) gateway.push(gatewayAddr);

  return { modelTee, gateway };
}
