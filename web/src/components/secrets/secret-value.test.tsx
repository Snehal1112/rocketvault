import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { SecretValue } from "@/components/secrets/secret-value"

const writeText = vi.fn(async () => undefined)

// jsdom exposes navigator.clipboard as a getter-only property, so it has to
// be redefined rather than assigned -- and userEvent.setup() installs its own
// clipboard stub, so this has to run after setup(), not only in beforeEach.
function stubClipboard() {
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  })
}

beforeEach(() => {
  writeText.mockClear()
  stubClipboard()
})

describe("SecretValue", () => {
  it("renders the value masked until Reveal is clicked", () => {
    render(<SecretValue value="s3cr3t" />)

    expect(screen.queryByText("s3cr3t")).not.toBeInTheDocument()
    expect(screen.getByText("••••••••")).toBeInTheDocument()
  })

  it("masks with a fixed width so the value's length does not leak", () => {
    render(<SecretValue value="a-very-long-secret-value-indeed" />)

    expect(screen.getByText("••••••••")).toBeInTheDocument()
  })

  it("shows the value after Reveal and re-masks after Hide", async () => {
    const user = userEvent.setup()
    render(<SecretValue value="s3cr3t" />)

    await user.click(screen.getByRole("button", { name: /reveal/i }))
    expect(screen.getByText("s3cr3t")).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: /hide/i }))
    expect(screen.queryByText("s3cr3t")).not.toBeInTheDocument()
  })

  it("calls onReveal only on the first reveal, for a lazily-fetched value", async () => {
    const user = userEvent.setup()
    const onReveal = vi.fn()
    render(<SecretValue value="s3cr3t" onReveal={onReveal} />)

    await user.click(screen.getByRole("button", { name: /reveal/i }))
    await user.click(screen.getByRole("button", { name: /hide/i }))

    expect(onReveal).toHaveBeenCalledTimes(1)
  })

  it("copies without revealing the value on screen", async () => {
    const user = userEvent.setup()
    stubClipboard()
    render(<SecretValue value="s3cr3t" />)

    await user.click(screen.getByRole("button", { name: /copy/i }))

    expect(writeText).toHaveBeenCalledWith("s3cr3t")
    expect(screen.queryByText("s3cr3t")).not.toBeInTheDocument()
    expect(await screen.findByText("Copied")).toBeInTheDocument()
  })

  it("re-masks when the underlying value changes", async () => {
    const user = userEvent.setup()
    const { rerender } = render(<SecretValue value="first" />)

    await user.click(screen.getByRole("button", { name: /reveal/i }))
    expect(screen.getByText("first")).toBeInTheDocument()

    rerender(<SecretValue value="second" />)

    expect(screen.queryByText("second")).not.toBeInTheDocument()
    expect(screen.getByText("••••••••")).toBeInTheDocument()
  })
})
