import { useState } from "react"
import { useNavigate } from "@tanstack/react-router"

import { login } from "@/api/auth"
import { OidcButton } from "@/components/auth/oidc-button"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldSeparator,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp"
import { setSession } from "@/lib/auth/auth-context"

// Deliberately generic -- matches the backend's own non-distinguishing 403
// for a bad username, password, or TOTP code (avoids account enumeration).
const GENERIC_LOGIN_ERROR = "Invalid username, password, or code."

export function LoginForm() {
  const navigate = useNavigate()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [totpCode, setTotpCode] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setIsSubmitting(true)

    try {
      const result = await login(username, password, totpCode)
      setSession(result.token, result.refreshToken, {
        id: result.userId,
        username: result.username,
        roles: result.roles,
      })
      navigate({ to: "/" })
    } catch {
      setError(GENERIC_LOGIN_ERROR)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="login-username">Username</FieldLabel>
          <FieldContent>
            <Input
              id="login-username"
              name="username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="login-password">Password</FieldLabel>
          <FieldContent>
            <Input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </FieldContent>
        </Field>
        <Field>
          <FieldLabel htmlFor="login-totp">Authenticator code</FieldLabel>
          <FieldContent>
            <InputOTP
              id="login-totp"
              maxLength={6}
              value={totpCode}
              onChange={setTotpCode}
            >
              <InputOTPGroup>
                <InputOTPSlot index={0} />
                <InputOTPSlot index={1} />
                <InputOTPSlot index={2} />
                <InputOTPSlot index={3} />
                <InputOTPSlot index={4} />
                <InputOTPSlot index={5} />
              </InputOTPGroup>
            </InputOTP>
            <FieldDescription>
              6-digit code from your authenticator app.
            </FieldDescription>
          </FieldContent>
        </Field>
        {error && <FieldError>{error}</FieldError>}
        <Button type="submit" disabled={isSubmitting} className="w-full">
          {isSubmitting ? "Signing in…" : "Sign in"}
        </Button>
        <FieldSeparator>or</FieldSeparator>
        <OidcButton />
      </FieldGroup>
    </form>
  )
}
