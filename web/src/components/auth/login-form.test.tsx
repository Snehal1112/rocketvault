import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

const { navigateMock } = vi.hoisted(() => ({ navigateMock: vi.fn() }))

vi.mock("@tanstack/react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-router")>()
  return { ...actual, useNavigate: () => navigateMock }
})

vi.mock("@/api/auth", () => ({ login: vi.fn() }))
vi.mock("@/api/config", () => ({ getConfig: vi.fn() }))

import { login } from "@/api/auth"
import { getConfig } from "@/api/config"
import { ApiError } from "@/api/types"
import { LoginForm } from "@/components/auth/login-form"
import * as authContext from "@/lib/auth/auth-context"

const loginMock = vi.mocked(login)
const getConfigMock = vi.mocked(getConfig)

beforeEach(() => {
  loginMock.mockReset()
  navigateMock.mockReset()
  getConfigMock.mockReset()
  getConfigMock.mockResolvedValue({
    feature_flags: {},
    public_api_url: "",
    sentry_dsn: "",
  })
  authContext.resetAuthStateForTests()
  localStorage.clear()
})

function renderLoginForm() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <LoginForm />
    </QueryClientProvider>
  )
}

async function fillAndSubmit() {
  await userEvent.type(screen.getByLabelText(/username/i), "alice")
  await userEvent.type(screen.getByLabelText(/password/i), "hunter2")
  await userEvent.type(screen.getByLabelText(/authenticator code/i), "123456")
  await userEvent.click(screen.getByRole("button", { name: /sign in/i }))
}

describe("LoginForm", () => {
  it("submits username, password, and totp code and navigates on success", async () => {
    loginMock.mockResolvedValueOnce({
      token: "t",
      refreshToken: "r",
      userId: "u1",
      username: "alice",
      roles: ["user"],
    })
    const setSessionSpy = vi.spyOn(authContext, "setSession")

    renderLoginForm()
    await fillAndSubmit()

    expect(loginMock).toHaveBeenCalledWith("alice", "hunter2", "123456")
    expect(setSessionSpy).toHaveBeenCalledWith("t", "r", {
      id: "u1",
      username: "alice",
      roles: ["user"],
    })
    expect(navigateMock).toHaveBeenCalledWith({ to: "/" })
  })

  it("shows a generic error on a failed login, not a field-specific one", async () => {
    loginMock.mockRejectedValueOnce(
      new ApiError({ message: "authentication failed", status_code: 403 })
    )

    renderLoginForm()
    await fillAndSubmit()

    expect(
      await screen.findByText(/invalid username, password, or code/i)
    ).toBeInTheDocument()
    expect(navigateMock).not.toHaveBeenCalled()
  })
})
