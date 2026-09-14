import { useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { PlusIcon } from "lucide-react"

import {
  createKey,
  type CreateKeyType,
  importKey,
  type Key,
  type KeyCurve,
} from "@/api/keys"
import { ApiError } from "@/api/types"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"

const RSA_SIZES = [2048, 3072, 4096]
const OCT_SIZES = [128, 192, 256]
const CURVES: KeyCurve[] = ["P-256", "P-384", "P-521", "P-256K"]

/** The backend takes `tags` as a plain string array (max 15), NOT a key=value
 * map like vaults do -- so a blank field sends nothing rather than []. */
function parseTags(raw: string): string[] | undefined {
  const tags = raw
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
  return tags.length > 0 ? tags : undefined
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}

/**
 * Generate or import a key. OCT is deliberately offered even on a
 * software-only deployment: no client-visible `hsm.enabled` signal exists, so
 * pre-disabling it would be a guess. The server's refusal is shown verbatim
 * instead, which also tells the operator exactly what to change.
 */
export function KeyCreateDialog({ vaultName }: { vaultName: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [tags, setTags] = useState("")
  const [type, setType] = useState<CreateKeyType>("RSA")
  const [rsaBits, setRsaBits] = useState(2048)
  const [octBits, setOctBits] = useState(256)
  const [curve, setCurve] = useState<KeyCurve>("P-256")
  const [jwk, setJwk] = useState("")
  const [error, setError] = useState<string | null>(null)

  async function onCreated(key: Key) {
    await queryClient.invalidateQueries({ queryKey: ["keys", vaultName] })
    setOpen(false)
    navigate({
      to: "/vaults/$vaultName/keys/$keyId",
      params: { vaultName, keyId: key.id },
    })
  }

  const generateMutation = useMutation({
    mutationFn: () =>
      createKey(vaultName, {
        name,
        type,
        ...(type === "RSA" ? { bits: rsaBits } : {}),
        ...(type === "OCT" ? { bits: octBits } : {}),
        ...(type === "ECDSA" ? { curve } : {}),
        tags: parseTags(tags),
      }),
    onSuccess: onCreated,
    onError: (mutationError) =>
      setError(errorMessage(mutationError, "Failed to create key.")),
  })

  const importMutation = useMutation({
    mutationFn: (parsed: Record<string, unknown>) =>
      importKey(vaultName, { name, jwk: parsed, tags: parseTags(tags) }),
    onSuccess: onCreated,
    onError: (mutationError) =>
      setError(errorMessage(mutationError, "Failed to import key.")),
  })

  function handleGenerate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    generateMutation.mutate()
  }

  function handleImport(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)

    let parsed: unknown
    try {
      parsed = JSON.parse(jwk)
    } catch {
      setError("That is not valid JSON. Paste the JWK object itself.")
      return
    }
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      setError("A JWK must be a JSON object.")
      return
    }

    importMutation.mutate(parsed as Record<string, unknown>)
  }

  async function handleJwkFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (file) {
      setJwk(await file.text())
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button />}>
        <PlusIcon />
        Create key
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create a key</DialogTitle>
          <DialogDescription>
            Generate new key material inside the vault, or import a private JWK
            you already hold.
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="key-create-name">Name</FieldLabel>
            <FieldContent>
              <Input
                id="key-create-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
              />
              <FieldDescription>
                Letters, digits and hyphens, starting with a letter.
              </FieldDescription>
            </FieldContent>
          </Field>
        </FieldGroup>

        <Tabs defaultValue="generate" className="mt-4">
          <TabsList>
            <TabsTrigger value="generate">Generate</TabsTrigger>
            <TabsTrigger value="import">Import</TabsTrigger>
          </TabsList>

          <TabsContent value="generate" className="pt-4">
            <form onSubmit={handleGenerate}>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="key-create-type">Type</FieldLabel>
                  <FieldContent>
                    <NativeSelect
                      id="key-create-type"
                      className="w-full"
                      value={type}
                      onChange={(event) =>
                        setType(event.target.value as CreateKeyType)
                      }
                    >
                      <NativeSelectOption value="RSA">RSA</NativeSelectOption>
                      <NativeSelectOption value="ECDSA">
                        ECDSA
                      </NativeSelectOption>
                      <NativeSelectOption value="OCT">
                        OCT (symmetric AES)
                      </NativeSelectOption>
                    </NativeSelect>
                    {type === "OCT" && (
                      <FieldDescription>
                        Symmetric keys require an HSM-backed deployment.
                      </FieldDescription>
                    )}
                  </FieldContent>
                </Field>

                {type === "RSA" && (
                  <Field>
                    <FieldLabel htmlFor="key-create-rsa-bits">
                      Key size
                    </FieldLabel>
                    <FieldContent>
                      <NativeSelect
                        id="key-create-rsa-bits"
                        className="w-full"
                        value={String(rsaBits)}
                        onChange={(event) =>
                          setRsaBits(Number(event.target.value))
                        }
                      >
                        {RSA_SIZES.map((size) => (
                          <NativeSelectOption key={size} value={String(size)}>
                            {size} bits
                          </NativeSelectOption>
                        ))}
                      </NativeSelect>
                    </FieldContent>
                  </Field>
                )}

                {type === "ECDSA" && (
                  <Field>
                    <FieldLabel htmlFor="key-create-curve">Curve</FieldLabel>
                    <FieldContent>
                      <NativeSelect
                        id="key-create-curve"
                        className="w-full"
                        value={curve}
                        onChange={(event) =>
                          setCurve(event.target.value as KeyCurve)
                        }
                      >
                        {CURVES.map((option) => (
                          <NativeSelectOption key={option} value={option}>
                            {option}
                          </NativeSelectOption>
                        ))}
                      </NativeSelect>
                      {curve === "P-256K" && (
                        <FieldDescription>
                          secp256k1 signs with ES256K. Hardware HSMs may refuse
                          this non-NIST curve.
                        </FieldDescription>
                      )}
                    </FieldContent>
                  </Field>
                )}

                {type === "OCT" && (
                  <Field>
                    <FieldLabel htmlFor="key-create-oct-bits">
                      Key size
                    </FieldLabel>
                    <FieldContent>
                      <NativeSelect
                        id="key-create-oct-bits"
                        className="w-full"
                        value={String(octBits)}
                        onChange={(event) =>
                          setOctBits(Number(event.target.value))
                        }
                      >
                        {OCT_SIZES.map((size) => (
                          <NativeSelectOption key={size} value={String(size)}>
                            {size} bits
                          </NativeSelectOption>
                        ))}
                      </NativeSelect>
                    </FieldContent>
                  </Field>
                )}

                <TagsField value={tags} onChange={setTags} />
                {error && <FieldError>{error}</FieldError>}
              </FieldGroup>
              <DialogFooter className="mt-6">
                <Button type="submit" disabled={generateMutation.isPending}>
                  {generateMutation.isPending ? "Generating…" : "Generate"}
                </Button>
              </DialogFooter>
            </form>
          </TabsContent>

          <TabsContent value="import" className="pt-4">
            <form onSubmit={handleImport}>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="key-create-jwk">
                    JWK (private)
                  </FieldLabel>
                  <FieldContent>
                    <Textarea
                      id="key-create-jwk"
                      className="min-h-32 font-heading text-xs"
                      placeholder='{"kty":"RSA","n":"…","e":"AQAB","d":"…"}'
                      value={jwk}
                      onChange={(event) => setJwk(event.target.value)}
                    />
                    <FieldDescription>
                      RSA or EC only, and it must carry private material — the
                      server rejects a public-only JWK. Symmetric JWKs cannot be
                      imported.
                    </FieldDescription>
                  </FieldContent>
                </Field>
                <Field>
                  <FieldLabel htmlFor="key-create-jwk-file">
                    Load from file
                  </FieldLabel>
                  <FieldContent>
                    <Input
                      id="key-create-jwk-file"
                      type="file"
                      accept="application/json,.json,.jwk"
                      onChange={handleJwkFile}
                    />
                  </FieldContent>
                </Field>
                <TagsField value={tags} onChange={setTags} />
                {error && <FieldError>{error}</FieldError>}
              </FieldGroup>
              <DialogFooter className="mt-6">
                <Button type="submit" disabled={importMutation.isPending}>
                  {importMutation.isPending ? "Importing…" : "Import"}
                </Button>
              </DialogFooter>
            </form>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}

/** Rendered inside both panels; only one is mounted at a time, so the two
 * never collide on the same id. */
function TagsField({
  value,
  onChange,
}: {
  value: string
  onChange: (next: string) => void
}) {
  return (
    <Field>
      <FieldLabel htmlFor="key-create-tags">Tags (optional)</FieldLabel>
      <FieldContent>
        <Input
          id="key-create-tags"
          placeholder="env=prod, owner=platform"
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
        <FieldDescription>
          Comma-separated labels, up to 15 of them.
        </FieldDescription>
      </FieldContent>
    </Field>
  )
}
