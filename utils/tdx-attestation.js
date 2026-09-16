#!/usr/bin/env node
import { createHash } from "node:crypto";
import { getCollateral, INTEL_PCS_URL, QuoteVerifier } from "@phala/dcap-qvl";

/**
 * Intel TCB statuses we accept. `OutOfDate` means Intel has published advisories
 * the host has not patched yet; the quote is still genuine, so we accept it and
 * print the advisories. Anything else (e.g. `Revoked`) fails.
 */
export const ACCEPTED_TCB_STATUSES = ["UpToDate", "SWHardeningNeeded", "OutOfDate"];

const hexToBytes = (hex) => Buffer.from(String(hex).replace(/^0x/i, ""), "hex");

/**
 * The first 32 bytes of report_data that should bind this attestation's signing key.
 *
 * - Without a TLS fingerprint: the signing address, right-padded with zeros to 32 bytes.
 * - With `tls_cert_fingerprint` (from `include_tls_fingerprint=true`):
 *   SHA256(signing_address_bytes || tls_fingerprint_bytes), which also proves the
 *   TLS key belongs to the TEE.
 * @param {Object} attestation - A gateway or model attestation
 * @returns {Buffer}
 */
export function expectedReportDataPrefix(attestation) {
  const address = hexToBytes(attestation.signing_address);
  if (attestation.tls_cert_fingerprint) {
    return createHash("sha256")
      .update(Buffer.concat([address, hexToBytes(attestation.tls_cert_fingerprint)]))
      .digest();
  }
  if (address.length > 32) throw new Error("Signing address is longer than 32 bytes");
  return Buffer.concat([address, Buffer.alloc(32 - address.length)]);
}

/**
 * Check a quote's report_data against the attestation's signing key and our nonce.
 * @param {Uint8Array} reportData - 64 bytes from the verified quote
 * @param {Object} attestation
 * @param {string} nonce - 64-char hex nonce we sent
 * @returns {{bindsSigningKey: boolean, bindsNonce: boolean}}
 */
export function checkReportData(reportData, attestation, nonce) {
  const data = Buffer.from(reportData);
  return {
    bindsSigningKey: data.subarray(0, 32).equals(expectedReportDataPrefix(attestation)),
    bindsNonce: data.subarray(32, 64).equals(hexToBytes(nonce)),
  };
}

/**
 * Verify an attestation's Intel TDX quote against Intel's root of trust, then check
 * that the hardware-signed report_data binds the signing key (and TLS key, if
 * present) and our nonce. Debug-mode TDs are rejected by the verifier.
 *
 * Without this step, `signing_address` and `request_nonce` are only values the
 * server reports about itself.
 *
 * @param {Object} attestation - `gateway_attestation` or an entry of `model_attestations`
 * @param {string} nonce - 64-char hex nonce we sent
 * @returns {Promise<{quoteValid: boolean, tcbStatus: string|null, advisoryIds: string[], tcbAccepted: boolean, bindsSigningKey: boolean, bindsNonce: boolean, tlsBound: boolean, passed: boolean, error?: string}>}
 */
export async function verifyTdxAttestation(attestation, nonce) {
  const result = {
    quoteValid: false,
    tcbStatus: null,
    advisoryIds: [],
    tcbAccepted: false,
    bindsSigningKey: false,
    bindsNonce: false,
    tlsBound: Boolean(attestation.tls_cert_fingerprint),
    passed: false,
  };
  try {
    if (!attestation.intel_quote) throw new Error("Attestation has no intel_quote");
    const quote = hexToBytes(attestation.intel_quote);
    const collateral = await getCollateral(INTEL_PCS_URL, quote);
    const verified = QuoteVerifier.newProd().verify(quote, collateral, Math.floor(Date.now() / 1000));
    result.quoteValid = true;
    result.tcbStatus = verified.status;
    result.advisoryIds = verified.advisory_ids ?? [];
    result.tcbAccepted = ACCEPTED_TCB_STATUSES.includes(verified.status);

    const td = verified.report.asTd10() ?? verified.report.asTd15()?.base;
    if (!td) throw new Error("Quote is not an Intel TDX quote");
    Object.assign(result, checkReportData(td.reportData, attestation, nonce));
  } catch (error) {
    result.error = error.message;
  }
  result.passed = result.quoteValid && result.tcbAccepted && result.bindsSigningKey && result.bindsNonce;
  return result;
}
