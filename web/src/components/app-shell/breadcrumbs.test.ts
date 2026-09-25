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

  it("links the certificates section once an identifier follows it", () => {
    const segments = buildBreadcrumbs("/vaults/payments/certificates")

    expect(segments[2]).toEqual({ label: "Certificates" })
    expect(
      buildBreadcrumbs("/vaults/payments/certificates/deleted")[2]
    ).toEqual({
      label: "Certificates",
      link: {
        to: "/vaults/$vaultName/certificates",
        params: { vaultName: "payments" },
      },
    })
  })

  it("links the keys section once a key id follows it", () => {
    const segments = buildBreadcrumbs("/vaults/payments/keys")

    expect(segments[2]).toEqual({ label: "Keys" })
    expect(buildBreadcrumbs("/vaults/payments/keys/deleted")[2]).toEqual({
      label: "Keys",
      link: {
        to: "/vaults/$vaultName/keys",
        params: { vaultName: "payments" },
      },
    })
  })

  it("treats a deleted-items tab as prose, not as an identifier", () => {
    expect(buildBreadcrumbs("/vaults/payments/keys/deleted")[3]).toEqual({
      label: "Deleted",
    })
  })

  it("abbreviates a uuid identifier so the trail stays readable", () => {
    const segments = buildBreadcrumbs(
      "/vaults/payments/keys/11111111-2222-3333-4444-555555555555"
    )

    expect(segments[3]).toEqual({ label: "11111111…", mono: true })
  })

  it("leaves a non-uuid identifier in full", () => {
    const segments = buildBreadcrumbs("/vaults/payments/secrets/db-password")

    expect(segments[3]).toEqual({ label: "db-password", mono: true })
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
