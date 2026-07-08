/**
 * lib/certs/sniff.js — cheap candidacy gate for the certificate / key-material scanner.
 *
 * Decides which files are worth opening, by extension OR conventional basename
 * (SSH key files like `id_rsa` / `authorized_keys` / `known_hosts` carry no
 * extension). The actual classification (cert vs private vs public vs keystore)
 * is content-based and lives in analyze.js — this module only narrows the walk.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

// Extensions worth opening: X.509 (pem/crt/cer/der), key material (key/pub),
// keystores (p12/pfx/jks/keystore), PuTTY (ppk), PGP (asc/gpg/pgp).
const EXT_RE = /\.(pem|crt|cer|der|key|pub|p12|pfx|jks|keystore|ppk|asc|gpg|pgp)$/i;

// Conventional SSH key files that carry NO extension. Covers every algorithm
// (rsa/dsa/ecdsa/ed25519 + FIDO `_sk` variants) plus the agent/host files.
const NAME_SET = new Set([
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
	"authorized_keys", "authorized_keys2", "known_hosts",
]);

/** True if `name` is worth opening for cert/key analysis. */
function isCandidate(name) {
	return EXT_RE.test(name) || NAME_SET.has(name);
}

module.exports = { isCandidate, EXT_RE, NAME_SET };
