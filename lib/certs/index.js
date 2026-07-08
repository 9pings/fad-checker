/**
 * lib/certs/index.js — public entrypoint for the certificate / key-material scanner.
 *
 * Not a codec (crypto material has no version/registry/CVE/EOL, so it doesn't fit
 * the codec contract). It's a standalone scanner, wired into runReportFlow like the
 * native-binary scan: discovers committed certificates, private/public keys (PEM,
 * OpenSSH every algorithm, PuTTY, PGP, SSH one-liners) and Java/PKCS#12 keystores,
 * then derives crypto-hygiene findings. 100% offline.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { scanCertificates } = require("./scan");
const { analyzeBuffer, worstSeverity } = require("./analyze");
const { isCandidate } = require("./sniff");

module.exports = { scanCertificates, analyzeBuffer, worstSeverity, isCandidate };
