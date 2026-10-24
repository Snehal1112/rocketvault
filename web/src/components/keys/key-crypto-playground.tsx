import { useState } from "react"
import { useMutation } from "@tanstack/react-query"
import { PlayIcon } from "lucide-react"

import {
  decryptData,
  encryptData,
  type Key,
  signData,
  unwrapKey,
  verifySignature,
  wrapKey,
} from "@/api/keys"
import { ApiError } from "@/api/types"
import { encodeUtf8Base64 } from "@/components/keys/base64"
import {
  algorithmsFor,
  type CryptoOperation,
  defaultAlgorithmFor,
  supportedOperations,
  usesNonce,
} from "@/components/keys/key-algorithms"
import { CopyValue } from "@/components/patterns/copy-value"
import { StatusDot } from "@/components/status-dot"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"

interface OperationConfig {
  label: string
  inputLabel: string
  /** Only the operations whose input is caller-supplied data (rather than
   * server-produced ciphertext) can sensibly take plain text. */
  allowsPlainText: boolean
  needsSignature: boolean
}

const OPERATIONS: Record<CryptoOperation, OperationConfig> = {
  sign: {
    label: "Sign",
    inputLabel: "Data to sign",
    allowsPlainText: true,
    needsSignature: false,
  },
  verify: {
    label: "Verify",
    inputLabel: "Signed data",
    allowsPlainText: false,
    needsSignature: true,
  },
  encrypt: {
    label: "Encrypt",
    inputLabel: "Data to encrypt",
    allowsPlainText: true,
    needsSignature: false,
  },
  decrypt: {
    label: "Decrypt",
    inputLabel: "Data to decrypt",
    allowsPlainText: false,
    needsSignature: false,
  },
  wrap: {
    label: "Wrap",
    inputLabel: "Key to wrap",
    allowsPlainText: false,
    needsSignature: false,
  },
  unwrap: {
    label: "Unwrap",
    inputLabel: "Wrapped key",
    allowsPlainText: false,
    needsSignature: false,
  },
}

type RunResult =
  | {
      kind: "value"
      operation: CryptoOperation
      algorithm: string
      value: string
      nonce?: string
      /** The input that produced it, so a follow-up round trip can reuse it. */
      source: string
    }
  | { kind: "verdict"; valid: boolean }

/** "" or a non-positive number means "use the current version", which the
 * backend expresses by omitting the field entirely. */
function parseVersion(raw: string): number | undefined {
  const parsed = Number(raw.trim())
  if (!raw.trim() || Number.isNaN(parsed) || parsed <= 0) {
    return undefined
  }
  return parsed
}

/**
 * A scratchpad for exercising a key. Only the operations and algorithms the
 * backend can actually perform on this key are offered -- see
 * key-algorithms.ts for why offering more would produce a 500 rather than a
 * useful error.
 */
export function KeyCryptoPlayground({
  vaultName,
  keyRecord,
}: {
  vaultName: string
  keyRecord: Key
}) {
  const operations = supportedOperations(keyRecord)
  const [operation, setOperation] = useState<CryptoOperation>(
    operations[0] ?? "sign"
  )
  const [algorithms, setAlgorithms] = useState<
    Partial<Record<CryptoOperation, string>>
  >({})
  const [input, setInput] = useState("")
  const [signature, setSignature] = useState("")
  const [nonce, setNonce] = useState("")
  const [version, setVersion] = useState("")
  const [plainText, setPlainText] = useState(false)
  const [result, setResult] = useState<RunResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const config = OPERATIONS[operation]
  const available = algorithmsFor(keyRecord, operation)
  const algorithm =
    algorithms[operation] ?? defaultAlgorithmFor(keyRecord, operation)
  const encodeInput = plainText && config.allowsPlainText

  const run = useMutation({
    mutationFn: async () => {
      const value = encodeInput ? encodeUtf8Base64(input) : input.trim()
      const selectedVersion = parseVersion(version)

      switch (operation) {
        case "sign": {
          const response = await signData(vaultName, keyRecord.id, {
            value,
            algorithm,
            version: selectedVersion,
          })
          return {
            kind: "value",
            operation,
            algorithm: response.algorithm,
            value: response.value,
            source: value,
          } satisfies RunResult
        }
        case "verify": {
          const response = await verifySignature(vaultName, keyRecord.id, {
            value,
            signature: signature.trim(),
            algorithm,
            version: selectedVersion,
          })
          return { kind: "verdict", valid: response.valid } satisfies RunResult
        }
        case "encrypt": {
          const response = await encryptData(vaultName, keyRecord.id, {
            value,
            algorithm,
            version: selectedVersion,
          })
          return {
            kind: "value",
            operation,
            algorithm: response.algorithm,
            value: response.value,
            nonce: response.nonce,
            source: value,
          } satisfies RunResult
        }
        case "decrypt": {
          const response = await decryptData(vaultName, keyRecord.id, {
            value,
            algorithm,
            nonce: nonce.trim() || undefined,
            version: selectedVersion,
          })
          return {
            kind: "value",
            operation,
            algorithm: response.algorithm,
            value: response.value,
            source: value,
          } satisfies RunResult
        }
        case "wrap": {
          const response = await wrapKey(vaultName, keyRecord.id, {
            plaintextKey: value,
            algorithm,
            version: selectedVersion,
          })
          return {
            kind: "value",
            operation,
            algorithm: response.algorithm,
            value: response.wrappedKey,
            source: value,
          } satisfies RunResult
        }
        default: {
          const response = await unwrapKey(vaultName, keyRecord.id, {
            wrappedKey: value,
            algorithm,
            version: selectedVersion,
          })
          return {
            kind: "value",
            operation,
            algorithm: response.algorithm,
            value: response.plaintextKey,
            source: value,
          } satisfies RunResult
        }
      }
    },
    onSuccess: (value) => {
      setError(null)
      setResult(value)
    },
    onError: (mutationError) => {
      setResult(null)
      setError(
        mutationError instanceof ApiError
          ? mutationError.message
          : "The operation failed."
      )
    },
  })

  function switchTo(next: CryptoOperation, prefill: () => void) {
    setOperation(next)
    setResult(null)
    setError(null)
    setPlainText(false)
    prefill()
  }

  function handleTabChange(next: string) {
    setOperation(next as CryptoOperation)
    setResult(null)
    setError(null)
  }

  if (operations.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Cryptographic operations</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            No cryptographic operations are available for this key type.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cryptographic operations</CardTitle>
        <CardDescription>
          Exercise this key directly. Inputs and outputs are standard base64.
          Only the algorithms this key supports are listed.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs value={operation} onValueChange={handleTabChange}>
          <TabsList className="flex-wrap">
            {operations.map((name) => (
              <TabsTrigger key={name} value={name}>
                {OPERATIONS[name].label}
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value={operation} className="pt-4">
            <form
              className="flex flex-col gap-4"
              onSubmit={(event) => {
                event.preventDefault()
                run.mutate()
              }}
            >
              <Field>
                <FieldLabel htmlFor="crypto-algorithm">Algorithm</FieldLabel>
                <FieldContent>
                  <NativeSelect
                    id="crypto-algorithm"
                    className="w-full"
                    value={algorithm}
                    onChange={(event) =>
                      setAlgorithms((previous) => ({
                        ...previous,
                        [operation]: event.target.value,
                      }))
                    }
                  >
                    {available.map((option) => (
                      <NativeSelectOption key={option} value={option}>
                        {option}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                </FieldContent>
              </Field>

              <Field>
                <FieldLabel htmlFor="crypto-version">Version</FieldLabel>
                <FieldContent>
                  <Input
                    id="crypto-version"
                    type="number"
                    min={1}
                    placeholder="Current"
                    value={version}
                    onChange={(event) => setVersion(event.target.value)}
                  />
                  <FieldDescription>
                    Leave blank to use the key's current version.
                  </FieldDescription>
                </FieldContent>
              </Field>

              {config.allowsPlainText && (
                <Field orientation="horizontal">
                  <FieldContent>
                    <FieldLabel htmlFor="crypto-plaintext">
                      Input is plain text
                    </FieldLabel>
                    <FieldDescription>
                      Encode what you type as base64 before sending it.
                    </FieldDescription>
                  </FieldContent>
                  <Switch
                    id="crypto-plaintext"
                    checked={plainText}
                    onCheckedChange={setPlainText}
                  />
                </Field>
              )}

              <Field>
                <FieldLabel htmlFor="crypto-input">
                  {config.inputLabel}
                </FieldLabel>
                <FieldContent>
                  <Textarea
                    id="crypto-input"
                    className="min-h-24 font-heading text-xs"
                    value={input}
                    onChange={(event) => setInput(event.target.value)}
                  />
                </FieldContent>
              </Field>

              {config.needsSignature && (
                <Field>
                  <FieldLabel htmlFor="crypto-signature">Signature</FieldLabel>
                  <FieldContent>
                    <Textarea
                      id="crypto-signature"
                      className="min-h-20 font-heading text-xs"
                      value={signature}
                      onChange={(event) => setSignature(event.target.value)}
                    />
                  </FieldContent>
                </Field>
              )}

              {operation === "decrypt" && usesNonce(algorithm) && (
                <Field>
                  <FieldLabel htmlFor="crypto-nonce">Nonce or IV</FieldLabel>
                  <FieldContent>
                    <Input
                      id="crypto-nonce"
                      className="font-heading text-xs"
                      value={nonce}
                      onChange={(event) => setNonce(event.target.value)}
                    />
                    <FieldDescription>
                      Returned by the matching encrypt call. Required for
                      AES-CBC and AES-GCM.
                    </FieldDescription>
                  </FieldContent>
                </Field>
              )}

              <div>
                <Button type="submit" disabled={run.isPending}>
                  <PlayIcon />
                  {run.isPending ? "Running…" : config.label}
                </Button>
              </div>
            </form>

            {error && (
              <p role="alert" className="mt-4 text-sm text-destructive">
                {error}
              </p>
            )}

            {result?.kind === "verdict" && (
              <div className="mt-4">
                <StatusDot
                  tone={result.valid ? "on" : "danger"}
                  label={
                    result.valid
                      ? "Signature is valid"
                      : "Signature is not valid for this data"
                  }
                />
              </div>
            )}

            {result?.kind === "value" && (
              <div className="mt-4 flex flex-col gap-3 rounded-3xl border p-4">
                <p className="text-sm text-muted-foreground">
                  Result ({result.algorithm})
                </p>
                <CopyValue value={result.value} label="result" />
                {result.nonce && (
                  <>
                    <p className="text-sm text-muted-foreground">Nonce or IV</p>
                    <CopyValue value={result.nonce} label="nonce" />
                  </>
                )}
                <FollowUpAction
                  result={result}
                  operations={operations}
                  onSwitch={switchTo}
                  setInput={setInput}
                  setSignature={setSignature}
                  setNonce={setNonce}
                  setAlgorithms={setAlgorithms}
                />
              </div>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}

/**
 * The inverse operation, prefilled. Signing then verifying by hand means
 * copying two base64 blobs between tabs; this is the single most common
 * thing an operator does in a playground like this.
 */
function FollowUpAction({
  result,
  operations,
  onSwitch,
  setInput,
  setSignature,
  setNonce,
  setAlgorithms,
}: {
  result: Extract<RunResult, { kind: "value" }>
  operations: CryptoOperation[]
  onSwitch: (next: CryptoOperation, prefill: () => void) => void
  setInput: (value: string) => void
  setSignature: (value: string) => void
  setNonce: (value: string) => void
  setAlgorithms: (
    update: (
      previous: Partial<Record<CryptoOperation, string>>
    ) => Partial<Record<CryptoOperation, string>>
  ) => void
}) {
  if (result.operation === "sign" && operations.includes("verify")) {
    return (
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() =>
            onSwitch("verify", () => {
              setInput(result.source)
              setSignature(result.value)
              setAlgorithms((previous) => ({
                ...previous,
                verify: result.algorithm,
              }))
            })
          }
        >
          Verify this signature
        </Button>
      </div>
    )
  }

  if (result.operation === "encrypt" && operations.includes("decrypt")) {
    return (
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() =>
            onSwitch("decrypt", () => {
              setInput(result.value)
              setNonce(result.nonce ?? "")
              setAlgorithms((previous) => ({
                ...previous,
                decrypt: result.algorithm,
              }))
            })
          }
        >
          Decrypt this output
        </Button>
      </div>
    )
  }

  if (result.operation === "wrap" && operations.includes("unwrap")) {
    return (
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() =>
            onSwitch("unwrap", () => {
              setInput(result.value)
              setAlgorithms((previous) => ({
                ...previous,
                unwrap: result.algorithm,
              }))
            })
          }
        >
          Unwrap this key
        </Button>
      </div>
    )
  }

  return null
}
