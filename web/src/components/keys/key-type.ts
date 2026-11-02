// The backend reports seven distinct `type` strings on a key response
// (verified against api/keys.go's buildKeyResponse): RSA, ECDSA, ES256K, oct,
// and the PKCS#11-backed RSA-HSM, EC-HSM, oct-HSM. Note that EC-HSM is the
// suffixed form of BOTH ECDSA and ES256K -- the distinction survives only in
// the `curve` field, which is why isSecp256k1 consults both.

export type KeyFamily = "rsa" | "ec" | "oct" | "unknown"

const HSM_SUFFIX = "-HSM"

/** True for a key whose private material lives in the HSM and never enters
 * the server process. Such keys expose no JWK components at all. */
export function isHsmBacked(type: string): boolean {
  return type.endsWith(HSM_SUFFIX)
}

function stripHsm(type: string): string {
  return isHsmBacked(type) ? type.slice(0, -HSM_SUFFIX.length) : type
}

/** Groups a reported type into the family that decides which crypto
 * operations and algorithms apply to it. */
export function keyFamily(type: string): KeyFamily {
  switch (stripHsm(type)) {
    case "RSA":
      return "rsa"
    case "ECDSA":
    case "ES256K":
    case "EC":
      return "ec"
    case "oct":
      return "oct"
    default:
      return "unknown"
  }
}

/** secp256k1 keys sign with ES256K rather than the NIST ES256/384/512 set. */
export function isSecp256k1(key: { type: string; curve?: string }): boolean {
  return stripHsm(key.type) === "ES256K" || key.curve === "P-256K"
}

/**
 * A one-line description of what the key is made of -- "RSA 3072",
 * "EC P-384", "AES 256". Symmetric keys are labelled AES rather than `oct`
 * because AES is the only symmetric algorithm this backend implements.
 */
export function describeKeyMaterial(key: {
  type: string
  bits?: number
  curve?: string
}): string {
  switch (keyFamily(key.type)) {
    case "rsa":
      return key.bits ? `RSA ${key.bits}` : "RSA"
    case "ec":
      return key.curve ? `EC ${key.curve}` : "EC"
    case "oct":
      return key.bits ? `AES ${key.bits}` : "AES"
    default:
      return key.type
  }
}
