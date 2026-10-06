import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/keys", () => ({
  getRotationPolicy: vi.fn(),
  setRotationPolicy: vi.fn(),
  clearRotationPolicy: vi.fn(),
}))

import {
  clearRotationPolicy,
  getRotationPolicy,
  type KeyRotationPolicy,
  setRotationPolicy,
} from "@/api/keys"
import { ApiError } from "@/api/types"
import { KeyRotationPolicyCard } from "@/components/keys/key-rotation-policy"
import { validateRotationPolicy } from "@/components/keys/rotation-policy-validation"

const getRotationPolicyMock = vi.mocked(getRotationPolicy)
const setRotationPolicyMock = vi.mocked(setRotationPolicy)
const clearRotationPolicyMock = vi.mocked(clearRotationPolicy)

const policy: KeyRotationPolicy = {
  id: "p1",
  keyId: "k1",
  userId: "u1",
  vaultId: "v1",
  rotateAfterDays: 90,
  notifyBeforeExpiryDays: 30,
  expiryDays: 365,
  enabled: true,
  nextRotationAt: "2026-04-01T00:00:00Z",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
}

function renderCard() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <KeyRotationPolicyCard vaultName="payments" keyId="k1" />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  getRotationPolicyMock.mockReset()
  setRotationPolicyMock.mockReset()
  clearRotationPolicyMock.mockReset()
})

describe("validateRotationPolicy", () => {
  it("accepts a disabled policy with any interval, matching the backend", () => {
    expect(
      validateRotationPolicy({
        rotateAfterDays: 0,
        notifyBeforeExpiryDays: 0,
        expiryDays: 0,
        enabled: false,
      })
    ).toBeNull()
  })

  it("rejects an enabled policy that rotates more often than every 7 days", () => {
    expect(
      validateRotationPolicy({
        rotateAfterDays: 3,
        notifyBeforeExpiryDays: 1,
        expiryDays: 30,
        enabled: true,
      })
    ).toMatch(/at least 7 days/i)
  })

  it("accepts an enabled policy at the 7-day boundary", () => {
    expect(
      validateRotationPolicy({
        rotateAfterDays: 7,
        notifyBeforeExpiryDays: 1,
        expiryDays: 30,
        enabled: true,
      })
    ).toBeNull()
  })

  it("rejects negative values outright", () => {
    expect(
      validateRotationPolicy({
        rotateAfterDays: 30,
        notifyBeforeExpiryDays: -1,
        expiryDays: 90,
        enabled: true,
      })
    ).toMatch(/cannot be negative/i)
  })
})

describe("KeyRotationPolicyCard", () => {
  it("treats a 404 as 'no schedule set' rather than an error", async () => {
    getRotationPolicyMock.mockRejectedValue(
      new ApiError({ status_code: 404, message: "rotation policy not found" })
    )

    renderCard()

    expect(
      await screen.findByText(/no automatic rotation schedule/i)
    ).toBeInTheDocument()
  })

  it("loads an existing schedule into the form", async () => {
    getRotationPolicyMock.mockResolvedValue(policy)

    renderCard()

    expect(await screen.findByLabelText(/rotate every/i)).toHaveValue(90)
    expect(screen.getByLabelText(/notify/i)).toHaveValue(30)
    expect(screen.getByLabelText(/expire after/i)).toHaveValue(365)
  })

  it("sends all four fields on save, since a partial body zeroes the rest", async () => {
    getRotationPolicyMock.mockResolvedValue(policy)
    setRotationPolicyMock.mockResolvedValue({ ...policy, rotateAfterDays: 60 })

    renderCard()

    const interval = await screen.findByLabelText(/rotate every/i)
    await userEvent.clear(interval)
    await userEvent.type(interval, "60")
    await userEvent.click(
      screen.getByRole("button", { name: /save schedule/i })
    )

    expect(setRotationPolicyMock).toHaveBeenCalledWith("payments", "k1", {
      rotateAfterDays: 60,
      notifyBeforeExpiryDays: 30,
      expiryDays: 365,
      enabled: true,
    })
  })

  it("blocks an invalid interval before it reaches the server", async () => {
    getRotationPolicyMock.mockResolvedValue(policy)

    renderCard()

    const interval = await screen.findByLabelText(/rotate every/i)
    await userEvent.clear(interval)
    await userEvent.type(interval, "2")
    await userEvent.click(
      screen.getByRole("button", { name: /save schedule/i })
    )

    expect(await screen.findByText(/at least 7 days/i)).toBeInTheDocument()
    expect(setRotationPolicyMock).not.toHaveBeenCalled()
  })

  it("clears the schedule behind a confirmation", async () => {
    getRotationPolicyMock.mockResolvedValue(policy)
    clearRotationPolicyMock.mockResolvedValue(undefined)

    renderCard()

    await userEvent.click(
      await screen.findByRole("button", { name: /remove schedule/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /^remove$/i }))

    expect(clearRotationPolicyMock).toHaveBeenCalledWith("payments", "k1")
  })
})
