#!/usr/bin/env node
import https from "node:https";
import tls from "node:tls";
import { X509Certificate, createHash } from "node:crypto";

/**
 * SHA-256 of a certificate's SubjectPublicKeyInfo (DER), as hex.
 * This is the fingerprint NEAR AI binds into TDX report_data when you request
 * `include_tls_fingerprint=true`.
 * @param {Buffer} certDer
 * @returns {string}
 */
export function spkiSha256(certDer) {
  const spki = new X509Certificate(certDer).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("hex");
}

/**
 * HTTPS request on a fresh connection that reports the server's TLS key and,
 * when `pinnedSpki` is given, refuses to send anything unless the server
 * presents that key. Normal certificate and host name checks still apply.
 *
 * @param {string} url
 * @param {{method?: string, headers?: Object, body?: string, pinnedSpki?: string|null}} [options]
 * @returns {Promise<{status: number, statusText: string, ok: boolean, text: string, spki: string}>}
 */
export function httpsRequest(url, options = {}) {
  const { method = "GET", headers = {}, body, pinnedSpki = null } = options;
  let spki = null;

  return new Promise((resolve, reject) => {
    const request = https.request(
      url,
      {
        method,
        headers,
        agent: false, // new connection, so the key we check is the key we use
        checkServerIdentity(host, cert) {
          const error = tls.checkServerIdentity(host, cert);
          if (error) return error;
          spki = spkiSha256(cert.raw);
          if (pinnedSpki && spki !== pinnedSpki.toLowerCase()) {
            return new Error(`TLS key ${spki} is not the attested key ${pinnedSpki}`);
          }
          return undefined;
        },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode,
            statusText: response.statusMessage,
            ok: response.statusCode >= 200 && response.statusCode < 300,
            // Exact bytes received; this string is what gets hashed and signed
            text: Buffer.concat(chunks).toString("utf8"),
            spki,
          })
        );
        response.on("error", reject);
      }
    );
    request.on("error", reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}
