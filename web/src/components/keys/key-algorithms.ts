import type { Key } from "@/api/keys"
import { isHsmBacked, isSecp256k1, keyFamily } from "@/components/keys/key-type"

// Which algorithm works with which key is NOT uniformly validated by the
// backend, so getting it wrong here produces an uncaught HTTP 500 with a
// leaked internal error rather than a clean 400. The matrix below is taken
// from internal/crypto/crypto_operations.go (the declared + reachable
// algorithms), internal/services/keys/crypto_service.go (the wrap/unwrap
// allow-list and its AES size check) and .claude/azure-keyvault-parity.md § 3,
// which records what is genuinely reachable end to end:
//
//   * Only wrap/unwrap validates its algorithm strictly (-> 400). Sign,
//     verify, encrypt and decrypt pass the string straight through, so an
//     unsupported value reaches getHasher/getCipher and 500s.
//   * Encrypt and wrap against an EC key 500 with a leaked parse error --
//     a known, unfixed rough edge (parity doc § 3, "Corrected 2026-08-19").
//     Azure does not support those on EC keys either, so this offers none.
//   * Every `oct` key is PKCS#11-backed (software oct creation is refused
//     outright), and the PKCS#11 provider's signMechanisms map has no HMAC
//     entry -- so HS256/384/512 are declared but unreachable, and are not
//     offered.
//   * AES key wrap requires the algorithm's size to equal the key's size, or
//     the service errors out (500). Only the matching one is offered.
//   * AES-CBC and AES-GCM are Encrypt/Decrypt-only: the wrap/unwrap contract
//     has no IV channel, so CBC wrapping returns unrecoverable ciphertext.

export type CryptoOperation =
  "sign" | "verify" | "encrypt" | "decrypt" | "wrap" | "unwrap"

const RSA_SIGNATURE_ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
]

const RSA_WRAP_ALGORITHMS = ["RSA-OAEP-256", "RSA-OAEP"]

/** The signature algorithm Azure pairs with each NIST curve. Offered first so
 * the default matches the key, while the others stay selectable -- the
 * backend accepts any of them against any NIST curve. */
const CURVE_ALGORITHM: Record<string, string> = {
  "P-256": "ES256",
  "P-384": "ES384",
  "P-521": "ES512",
}

const NIST_EC_ALGORITHMS = ["ES256", "ES384", "ES512"]

/** Modes whose ciphertext cannot be decrypted without the IV/nonce the
 * encrypt call returned. */
const NONCE_ALGORITHMS = new Set([
  "AES256-GCM",
  "A128CBC",
  "A192CBC",
  "A256CBC",
])

export function usesNonce(algorithm: string): boolean {
  return NONCE_ALGORITHMS.has(algorithm)
}

function ecSignatureAlgorithms(key: Key): string[] {
  if (isSecp256k1(key)) {
    return ["ES256K"]
  }
  const preferred = key.curve ? CURVE_ALGORITHM[key.curve] : undefined
  if (!preferred) {
    return NIST_EC_ALGORITHMS
  }
  return [preferred, ...NIST_EC_ALGORITHMS.filter((alg) => alg !== preferred)]
}

function octEncryptAlgorithms(bits: number | undefined): string[] {
  if (!bits) {
    return []
  }
  const algorithms = [`A${bits}CBC`]
  // The backend only models a 256-bit GCM identifier.
  if (bits === 256) {
    algorithms.push("AES256-GCM")
  }
  return algorithms
}

/** Every algorithm that is safe to offer for `operation` on `key`. An empty
 * result means the operation is not supported for this key at all. */
export function algorithmsFor(key: Key, operation: CryptoOperation): string[] {
  switch (keyFamily(key.type)) {
    case "rsa":
      if (operation === "sign" || operation === "verify") {
        return RSA_SIGNATURE_ALGORITHMS
      }
      if (operation === "encrypt" || operation === "decrypt") {
        // RSA1_5 is implemented for software keys only -- no PKCS#11
        // mechanism exists for it.
        return isHsmBacked(key.type)
          ? [...RSA_WRAP_ALGORITHMS]
          : [...RSA_WRAP_ALGORITHMS, "RSA1_5"]
      }
      return [...RSA_WRAP_ALGORITHMS]

    case "ec":
      if (operation === "sign" || operation === "verify") {
        return ecSignatureAlgorithms(key)
      }
      return []

    case "oct":
      if (operation === "sign" || operation === "verify") {
        return []
      }
      if (operation === "encrypt" || operation === "decrypt") {
        return octEncryptAlgorithms(key.bits)
      }
      return key.bits ? [`A${key.bits}KW`] : []

    default:
      return []
  }
}

const ALL_OPERATIONS: CryptoOperation[] = [
  "sign",
  "verify",
  "encrypt",
  "decrypt",
  "wrap",
  "unwrap",
]

/** The operations worth showing a tab for -- an operation with no usable
 * algorithm would only produce a 500. */
export function supportedOperations(key: Key): CryptoOperation[] {
  return ALL_OPERATIONS.filter(
    (operation) => algorithmsFor(key, operation).length > 0
  )
}

export function defaultAlgorithmFor(
  key: Key,
  operation: CryptoOperation
): string {
  return algorithmsFor(key, operation)[0] ?? ""
}
