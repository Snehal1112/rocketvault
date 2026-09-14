import { describe, expect, it } from "vitest"

import { buildBreadcrumbs } from "@/components/app-shell/breadcrumbs"

describe("buildBreadcrumbs", () => {
  it("renders the vault picker as a single, link-less crumb", () => {
    expect(buildBreadcrumbs("/vaults")).toEqual([{ label: "Vaults" }])
  })

  it("marks the vault name as monospace and links the parent crumb", () => {
    expect(buildBreadcrumbs("/vaults/payments/settings")).toEqual([
      { label: "Vaults", link: { to: "/vaults" } },
      {
        label: "payments",
        mono: true,
        link: {
          to: "/vaults/$vaultName/secrets",
          params: { vaultName: "payments" },
        },
      },
      { label: "Settings" },
    ])
  })

  it("never links the last crumb, even when the section has a route", () => {
    const segments = buildBreadcrumbs("/vaults/payments/secrets")

    expect(segments[segments.length - 1]).toEqual({ label: "Secrets" })
  })

  it("links the section once a deeper identifier follows it", () => {
    expect(buildBreadcrumbs("/vaults/payments/secrets/db-password")).toEqual([
      { label: "Vaults", link: { to: "/vaults" } },
      {
        label: "payments",
        mono: true,
        link: {
          to: "/vaults/$vaultName/secrets",
          params: { vaultName: "payments" },
        },
      },
      {
        label: "Secrets",
        link: {
          to: "/vaults/$vaultName/secrets",
          params: { vaultName: "payments" },
        },
      },
      { label: "db-password", mono: true },
    ])
  })

  it("leaves an unbuilt vault section readable but unlinked", () => {
    const segments = buildBreadcrumbs("/vaults/payments/keys")

    expect(segments[2]).toEqual({ label: "Keys" })
  })

  it("handles admin paths", () => {
    expect(buildBreadcrumbs("/admin")).toEqual([{ label: "Admin" }])
    expect(buildBreadcrumbs("/admin/service-accounts")).toEqual([
      { label: "Admin", link: { to: "/admin" } },
      { label: "Service accounts" },
    ])
  })

  it("falls back to a single crumb for anything else", () => {
    expect(buildBreadcrumbs("/account")).toEqual([{ label: "Account" }])
    expect(buildBreadcrumbs("/")).toEqual([{ label: "RocketVault" }])
  })
})
