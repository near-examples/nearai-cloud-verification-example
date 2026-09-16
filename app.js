#!/usr/bin/env node
import chalk from "chalk";
import {
  decodeNvidiaAttestation,
  summarizeGpuAttestation,
  extractSigningAddresses,
} from "./utils/model-attestation.js";
import {
  getModelAttestation,
  getGpuAttestation,
  NEARAI_BASE_URL,
  NVIDIA_NRAS_URL,
} from "./utils/api.js";
import { sendAndVerifyChatMessage } from "./utils/send-and-verify-chat.js";
import { generateNonce } from "./utils/verification-helpers.js";
import { verifyTdxAttestation } from "./utils/tdx-attestation.js";

// You can change this to any TEE-hosted model you want to test
// See available models at: https://docs.near.ai/cloud/models
const MODEL_NAME = process.env.MODEL_NAME || "zai-org/GLM-5.1-FP8";
const CHAT_CONTENT = "Respond with only two words";
// stream=false -> the model TEE signs the response (signature_kind: provider_tee)
// stream=true  -> the gateway TEE signs the exact bytes you receive (signature_kind: gateway)
const STREAM = process.env.STREAM === "true";

const log = console.log;
const ok = (pass) => (pass ? "✅" : "❌");
const checks = [];
function check(name, pass) {
  checks.push({ name, pass });
  return pass;
}

function printSummary() {
  const failed = checks.filter((c) => !c.pass);
  log(chalk.bold("\n\n📋 Summary"));
  log("--------------------------------");
  for (const c of checks) log(`   ${ok(c.pass)} ${c.name}`);
  return failed.length;
}

function logTdx(label, tdx) {
  log(`       ${label}:`);
  log(`         ${ok(tdx.quoteValid)} Intel TDX quote verified against Intel's root of trust (non-debug TD)`);
  if (tdx.tcbStatus) {
    const advisories = tdx.advisoryIds.length ? chalk.dim(` (advisories: ${tdx.advisoryIds.join(", ")})`) : "";
    log(`         ${ok(tdx.tcbAccepted)} Platform TCB status: ${tdx.tcbStatus}${advisories}`);
  }
  log(`         ${ok(tdx.bindsSigningKey)} report_data binds the signing address${tdx.tlsBound ? " + TLS key" : ""}`);
  log(`         ${ok(tdx.bindsNonce)} report_data binds our nonce`);
  if (tdx.error) log(`         ${chalk.red(tdx.error)}`);
}

async function main() {
  try {
    log(chalk.bold("\n\n🚀 Starting NEAR AI Cloud Verification Demo"));
    log(`   API Key configured: ${process.env.NEARAI_CLOUD_API_KEY ? chalk.bold.green("Yes") : chalk.bold.red("No")}`);
    log("===============================================");
    log(chalk.dim("  - Get an attestation report (gateway + model TEEs) from NEAR AI Confidential Cloud"));
    log(chalk.dim("  - Verify the Intel TDX quotes and what they bind (signing keys, nonce, gateway TLS key)"));
    log(chalk.dim("  - Verify the GPU attestation w/ NVIDIA's attestation service (signed token, nonce freshness)"));
    log(chalk.dim("  - Only if everything passed: send a Chat Message Request over the attested TLS key"));
    log(chalk.dim("  - Verify the response hashes and TEE signature\n\n"));

    // ------------------------------------------------------------------
    // Step 1: Get attestation report (with a fresh nonce for replay protection)
    // ------------------------------------------------------------------
    log(chalk.bold("1) Getting NEAR AI Cloud attestation report:"));
    log("--------------------------------");
    log(`🌐 NEAR AI Cloud Endpoint: ${chalk.bold.blue(`${NEARAI_BASE_URL}/v1/attestation/report`)}`);
    const nonce = generateNonce();
    log(`   AI Model:        ${chalk.cyan(MODEL_NAME)}`);
    log(`   Request Nonce:   ${chalk.dim(nonce)}`);

    const { report: attestationReport, liveSpki } = await getModelAttestation(MODEL_NAME, { nonce });
    const signingAddresses = extractSigningAddresses(attestationReport);
    const modelAttestations = attestationReport.model_attestations ?? [];

    log(`\n   GATEWAY TEE SIGNING ADDRESS:  ${chalk.yellow(signingAddresses.gateway.join(", ") || "(none)")}`);
    log(`   MODEL TEE SIGNING ADDRESSES:  ${chalk.yellow(signingAddresses.modelTee.join(", ") || "(none)")}`);

    const gatewayNonceOk = attestationReport.gateway_attestation?.request_nonce === nonce;
    const modelNoncesOk =
      modelAttestations.length > 0 &&
      modelAttestations.every((a) => a.request_nonce === nonce);
    log(`\n   ${ok(gatewayNonceOk)} Gateway attestation echoes our nonce`);
    log(`   ${ok(modelNoncesOk)} Model attestation(s) echo our nonce (${modelAttestations.length} TEE node(s))`);
    check("Attestation report returned model TEE(s)", signingAddresses.modelTee.length > 0);
    check("Attestation nonce echoed (gateway)", gatewayNonceOk);
    check("Attestation nonce echoed (model TEEs)", modelNoncesOk);

    // ------------------------------------------------------------------
    // Step 2: Verify Intel TDX quotes (gateway + every model TEE node)
    // ------------------------------------------------------------------
    // Until this passes, the signing addresses and echoed nonces above are only
    // values the server reports about itself.
    log(chalk.bold("\n\n2) Verifying Intel TDX quotes:"));
    log("--------------------------------");
    log(`🌐 Intel collateral: ${chalk.bold.blue("https://api.trustedservices.intel.com")}\n`);

    const gateway = attestationReport.gateway_attestation;
    let gatewayTlsBound = false;
    if (gateway) {
      const gatewayTdx = await verifyTdxAttestation(gateway, nonce);
      logTdx(`Gateway TEE ${chalk.yellow(gateway.signing_address)}`, gatewayTdx);
      // The gateway TLS key is inside its hardware-signed report_data; the
      // connection we fetched the report over must present that same key.
      gatewayTlsBound =
        gatewayTdx.passed &&
        gatewayTdx.tlsBound &&
        String(gateway.tls_cert_fingerprint).toLowerCase() === liveSpki;
      log(`         ${ok(gatewayTlsBound)} This connection's TLS key is the attested gateway key (TLS ends inside the TEE)`);
      log(chalk.dim(`           live ${liveSpki} / attested ${gateway.tls_cert_fingerprint ?? "(not provided)"}`));
      check("Gateway Intel TDX quote verified (signing key + nonce bound)", gatewayTdx.passed);
    } else {
      log("   ❌ No gateway attestation in report");
      check("Gateway Intel TDX quote verified (signing key + nonce bound)", false);
    }
    check("Gateway TLS key bound to its quote and matches this connection", gatewayTlsBound);

    let allModelsPassed = modelAttestations.length > 0;
    for (let i = 0; i < modelAttestations.length; i++) {
      const attestation = modelAttestations[i];
      const tdx = await verifyTdxAttestation(attestation, nonce);
      logTdx(`Model TEE ${i + 1}/${modelAttestations.length} ${chalk.yellow(attestation.signing_address)}`, tdx);
      allModelsPassed &&= tdx.passed;
    }
    check("Model Intel TDX quotes verified (all TEE nodes, signing keys + nonce bound)", allModelsPassed);

    // ------------------------------------------------------------------
    // Step 3: Verify GPU attestation with NVIDIA
    // ------------------------------------------------------------------
    const nvidiaPayloads = modelAttestations
      .filter((a) => a.nvidia_payload)
      .map((a) => ({ signingAddress: a.signing_address, payload: a.nvidia_payload }));

    if (nvidiaPayloads.length > 0) {
      log(chalk.bold("\n\n3) Verifying GPU attestation with NVIDIA:"));
      log("--------------------------------");
      log(`🌐 NVIDIA Attestation Endpoint: ${chalk.bold.blue(NVIDIA_NRAS_URL)}`);
      log(`📊 Found ${nvidiaPayloads.length} NVIDIA payload(s) to verify \n`);

      let allPassed = true;
      log("    🔍 Verifying NVIDIA payloads:");
      log("       --------------------------------");
      for (let i = 0; i < nvidiaPayloads.length; i++) {
        const { signingAddress, payload } = nvidiaPayloads[i];

        // The payload NEAR AI hands us must carry the nonce we asked for
        let payloadNonceOk = false;
        try {
          const parsed = typeof payload === "string" ? JSON.parse(payload) : payload;
          payloadNonceOk = parsed?.nonce?.toLowerCase() === nonce;
        } catch {
          payloadNonceOk = false;
        }

        const gpuVerification = await getGpuAttestation(payload);
        const summary = summarizeGpuAttestation(await decodeNvidiaAttestation(gpuVerification), nonce);
        const passed =
          summary.tokenVerified && summary.overallResult && summary.nonceMatch === true && payloadNonceOk;
        allPassed &&= passed;

        log(`       Payload ${i + 1}/${nvidiaPayloads.length} (TEE ${chalk.yellow(signingAddress)}):`);
        log(`         ${ok(summary.tokenVerified)} NVIDIA token signature verified against NVIDIA's published keys`);
        log(`         ${ok(summary.overallResult)} NVIDIA overall attestation result`);
        log(`         ${ok(payloadNonceOk)} Payload nonce matches request nonce`);
        log(`         ${ok(summary.nonceMatch)} NVIDIA token eat_nonce matches request nonce`);
        for (const gpu of summary.gpus) {
          log(chalk.dim(`         ${gpu.key}: ${gpu.hwmodel} | driver ${gpu.driverVersion} | vbios ${gpu.vbiosVersion} | secboot=${gpu.secureBoot} | debug=${gpu.debugStatus}`));
        }
      }
      log("       --------------------------------");
      log(`       RESULT: ${nvidiaPayloads.length} NVIDIA payload(s) checked -> ${allPassed ? "✅ ALL PASSED" : "❌ SOME FAILED"}`);
      check("NVIDIA GPU attestation (all TEE nodes)", allPassed);
    } else {
      log("\n⚠️  No NVIDIA payload found in attestation report");
      log("💡 This might mean:");
      log("   - The model is a third-party (non-TEE) model proxied through the gateway");
      log("   - The model name is wrong; see https://docs.near.ai/cloud/models for TEE-hosted models");
      check("NVIDIA GPU attestation (all TEE nodes)", false);
    }

    // Never send a prompt to an enclave that failed verification
    if (checks.some((c) => !c.pass)) {
      const failedCount = printSummary();
      log(chalk.bold.red(`\n❌  ${failedCount} attestation check(s) failed: not sending the chat message.`));
      process.exit(1);
    }

    // ------------------------------------------------------------------
    // Step 4: Send and verify chat message
    // ------------------------------------------------------------------
    log(chalk.bold("\n\n4) Sending and verifying chat message..."));
    log("--------------------------------");
    log(`🌐 NEAR AI Cloud Endpoint: ${chalk.bold.blue(`${NEARAI_BASE_URL}/v1/chat/completions`)}`);
    log(`   TEE AI Model:     ${chalk.cyan(MODEL_NAME)}`);
    log(`   Chat Msg Sent:    ${chalk.cyan(CHAT_CONTENT)}`);
    log(`   Streaming:        ${chalk.cyan(String(STREAM))}`);
    log(`   Pinned TLS key:   ${chalk.dim(liveSpki)}`);

    // Pinned to the attested gateway TLS key: the request is refused before
    // anything is sent if a different server answers.
    const chatResult = await sendAndVerifyChatMessage(CHAT_CONTENT, MODEL_NAME, signingAddresses, {
      stream: STREAM,
      pinnedSpki: liveSpki,
    });
    const { hashValidation, signatureValidation, signatureKind, signatureKindMatch } = chatResult;

    log(`   Returned Chat ID: ${chalk.cyan(chatResult.response.chatId)}`);
    log(`   Signature Kind:   ${chalk.cyan(signatureKind)} ${chalk.dim(
      signatureKind === "gateway"
        ? "(gateway TEE signed the exact bytes you received)"
        : "(model TEE signed the request/response it processed)"
    )}`);
    log(`   ${ok(signatureKindMatch)} Signature kind matches signed payload format`);
    check("Signature kind matches signed payload format", signatureKindMatch);

    log(`\n   ${chalk.bold(" 🔎 Checking if hash values match:")}`);
    log("       --------------------------------");
    if (hashValidation.signedModelId !== null && hashValidation.signedModelId !== undefined) {
      log(`     ⋅ MODEL ID ${ok(hashValidation.modelIdMatch)}`);
      log(`       Requested:          ${chalk.yellow(MODEL_NAME)}`);
      log(`       Signed:             ${chalk.yellow(hashValidation.signedModelId)}`);
    }
    log(`     → REQUEST HASH ${ok(hashValidation.requestHashMatch)}`);
    log(`       Sent   (Expected):  ${chalk.yellow(chatResult.requestHash)}`);
    log(`       Signed (Actual):    ${chalk.yellow(hashValidation.signedRequestHash)}`);
    log(`     ← RESPONSE HASH ${ok(hashValidation.responseHashMatch)}`);
    log(`       Received (Expected):${chalk.yellow(chatResult.responseHash)}`);
    log(`       Signed   (Actual):  ${chalk.yellow(hashValidation.signedResponseHash)}`);
    log("       --------------------------------");
    if (hashValidation.error) log(`       ${chalk.red(hashValidation.error)}`);
    log(`       RESULT: ${hashValidation.valid ? "✅ HASHES VALID" : "❌ HASHES INVALID"}`);
    check("Request/response hashes match signed text", hashValidation.valid);

    log(`\n    ${chalk.bold("🔑 Verifying signature returned by NEAR AI Cloud:")}`);
    log("       --------------------------------");
    log(`       Expected ${signatureKind === "gateway" ? "Gateway" : "Model"} TEE Address(es): ${chalk.yellow(signatureValidation.expectedAddresses.join(", "))}`);
    log(`       Recovered Signer Address:      ${chalk.yellow(signatureValidation.recoveredAddress)}`);
    log("       --------------------------------");
    if (signatureValidation.error) log(`       ${chalk.red(signatureValidation.error)}`);
    log(`       RESULT: ${signatureValidation.valid ? "✅ SIGNATURE VERIFIED" : "❌ SIGNATURE INVALID"}`);
    check(`Signature recovered to attested ${signatureKind === "gateway" ? "gateway" : "model"} TEE address`, signatureValidation.valid);

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    const failedCount = printSummary();
    if (failedCount === 0) {
      log(chalk.bold.green("\n✅  Verification Demo complete: all checks passed!"));
    } else {
      log(chalk.bold.red(`\n❌  Verification Demo complete: ${failedCount} check(s) failed`));
      process.exit(1);
    }
  } catch (error) {
    console.error("\n❌ Error occurred:");
    console.error(`   ${error.message}`);
    console.error(`   Error type: ${error.constructor.name}`);

    if (error.message.includes("401") || error.message.includes("Authorization")) {
      console.error("\n💡 Tip: Make sure your NEARAI_CLOUD_API_KEY is set in the .env file");
    } else if (error.message.includes("fetch")) {
      console.error("\n💡 Tip: Check your internet connection and API endpoints");
    } else if (error.message.includes("404") || /not found/i.test(error.message)) {
      console.error("\n💡 Tip: The model name might not exist or be available. See https://docs.near.ai/cloud/models");
    }

    process.exit(1);
  }
}

main();
