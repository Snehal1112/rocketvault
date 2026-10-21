/**
 * Shared className for the `<Link>` wrapping a resource card: block-level,
 * fills the grid cell, and carries the focus-visible ring the card itself
 * doesn't need (the ring belongs to the interactive link, not the card
 * surface). Split into its own non-component module because Biome's
 * useComponentExportOnlyModules rule forbids a component file
 * (card-grid.tsx) from also exporting a plain constant.
 *
 * A constant rather than a component because TanStack Router's `Link` is
 * generically typed per-route (`to`/`params` are checked against the actual
 * route tree) -- wrapping it in a shared component would either lose that
 * type-checking or need generics disproportionate to what three call sites
 * need. The remaining `<Link to=... params=...>` boilerplate at each call
 * site is the type-safe part; only its styling is shared here.
 */
export const RESOURCE_CARD_LINK_CLASS =
  "group block h-full rounded-4xl outline-none focus-visible:ring-3 focus-visible:ring-ring/30"
