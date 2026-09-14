# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

The web front-end for **RocketVault**, the self-hosted Azure Key Vault alternative
whose Go backend lives in the parent directory (`../`, see `../CLAUDE.md` for the
API, auth model, and multi-vault RBAC concepts the UI has to reflect). `web/` is
its own git repository, currently a fresh Vite scaffold — `src/App.tsx` is still
the generated placeholder page, so most product UI is yet to be built.

## Commands

The package manager is **bun** (`bun.lock` is committed — do not switch to
npm/yarn/pnpm, it would create a second lockfile).

```bash
bun install
bun run dev         # Vite dev server
bun run build       # tsc -b && vite build
bun run typecheck   # tsc -b --noEmit
bun run lint        # biome lint --error-on-warnings
bun run lint:fix    # biome lint --write --error-on-warnings
bun run format      # prettier --write "**/*.{ts,tsx}"
bun run test        # vitest run
bun run test:watch  # vitest (watch mode)
```

Vitest + React Testing Library + jsdom are wired up (`vitest.config.ts` extends
`vite.config.ts` via `mergeConfig`; setup file: `src/test/setup.ts`). Do not
assume `bun test` (Bun's own built-in runner) is configured — `bun run test`
is the vitest script.

Two flags in those scripts are load-bearing; both guard against a check that
silently passes while inspecting nothing:

- `typecheck` must keep **`-b`**. The root `tsconfig.json` is a solution file
  (`"files": []` plus project references), and a plain `tsc --noEmit` does not
  follow references — it would check zero files and always exit 0.
- `lint` must keep **`--error-on-warnings`**. Most Biome rules, including
  `noExplicitAny`, report at warning level, and plain `biome lint` exits 0 on
  warnings — so an `any` could land in `src/` with a green lint run.

## Styling: Tailwind first, styled-components available

Tailwind v4 is the primary styling system — all 61 vendored components use it.
`styled-components` v6 is also installed and may be used for prop-driven or
dynamic styles that utility classes express poorly. Prefer Tailwind (and `cva`,
already used by every vendored component) for variants before reaching for it.

**SCSS was considered and rejected.** Tailwind v4's docs state it "is not
designed to be used with CSS preprocessors like Sass, Less, or Stylus" — Tailwind
is itself the preprocessor. Its `@import` bundling, Lightning CSS nesting, and
custom properties already cover what SCSS would provide. For scoped styles that
do not need Tailwind, use CSS Modules (`*.module.css`), which Vite supports with
no dependency. Do not add `sass`.

### The token bridge

There is deliberately **no styled-components `ThemeProvider`**. Theming works
through the CSS custom properties in `src/index.css`, so `var(--card)` inside a
styled block follows dark mode for free — the `.dark` class on `<html>`
reassigns the variables. See `src/components/styled/example.tsx` for the
reference pattern, including transient (`$`-prefixed) props.

**Only tokens in the plain `:root`/`.dark` blocks exist at runtime.** Tokens
declared inside `@theme inline` — `--font-sans`, `--font-heading`, `--radius-lg`
and every `--color-*` — are inlined into Tailwind utilities and are *not* emitted
as CSS variables, so `var(--radius-lg)` silently resolves to nothing in a styled
block. Use the base token (`var(--radius)`) instead. Verify with
`grep -- '--token:' dist/assets/index-*.css` after a build if unsure.

### Tooling blind spot

Prettier *does* format CSS inside styled template literals. **Biome does not lint
it at all** — a misspelled property or an empty value passes every check in this
repo. CSS inside styled blocks is unverified by tooling, so review it by eye.

`@vitejs/plugin-react` v6 uses Oxc, not Babel, and exposes no `babel` option, so
`babel-plugin-styled-components` cannot be wired in. Class names are therefore
hashed (`sc-bdVaJa`) rather than readable in DevTools; this is a known, accepted
trade. Getting readable names would mean switching to `@vitejs/plugin-react-swc`
plus `@swc/plugin-styled-components`, or adding a second Babel pass.

## Components

**The entire shadcn registry is already vendored** — all 61 components are in
`src/components/ui/`, plus `src/hooks/use-mobile.ts`. Do not run `shadcn add`
for a component that is already there; just import it. See
[.claude/shadcn-components.md](.claude/shadcn-components.md) for the full
inventory: every file, its exported symbols, its external dependency, and the
components grouped by purpose.

These are vendored copies, not a node_modules package — they are yours to edit.
They are currently byte-identical to the registry, which is what lets a future
`shadcn add --overwrite` upgrade apply cleanly, so prefer wrapping or composing
over editing one in place.

Five components need a context provider mounted above them before they work:
`TooltipProvider`, `SidebarProvider`, `ToastProvider`, `MessageScrollerProvider`,
and `DirectionProvider` (the last is re-exported from
`@base-ui/react/direction-provider`). **None of these are mounted yet** —
`src/main.tsx` currently wraps `<App />` in `ThemeProvider` only. Add the ones
you need when you first use those components.

## Stack and conventions

- **React 19 + TypeScript (strict)** on **Vite**. `tsconfig.app.json` enables
  `noUnusedLocals`, `noUnusedParameters`, `verbatimModuleSyntax`, and
  `erasableSyntaxOnly` — type-only imports must use `import type`, and enums or
  parameter properties will not compile.
- **`@/` maps to `src/`**, declared in both `vite.config.ts` and
  `tsconfig.app.json`. Keep the two in sync if either changes.
- **Tailwind CSS v4, CSS-first.** There is no `tailwind.config.js`; all design
  tokens live in `src/index.css` under `:root` / `.dark` (oklch values) and are
  exposed to Tailwind via `@theme inline`. Add or change a color, radius, or
  font there, never in a JS config. Dark mode is a `.dark` class on `<html>`
  driven by `@custom-variant dark`.
- **shadcn/ui in the `base-luma` style, built on `@base-ui/react` — not Radix.**
  Component props extend the Base UI primitive's types (see
  `src/components/ui/button.tsx`: `ButtonPrimitive.Props & VariantProps<...>`).
  Follow that shape for new components: `cva` for variants, `cn()` from
  `@/lib/utils` to merge classes, a `data-slot` attribute on the root element.
  Icons come from `lucide-react`.
- **Biome (`biome.json`) is the linter; Prettier is the formatter.** ESLint was
  removed entirely. The division is deliberate: Biome's formatter, and its
  `assist` organize-imports action, are both explicitly disabled so the two tools
  never fight over the same file. Do not enable Biome's formatter —
  `prettier-plugin-tailwindcss` sorts Tailwind classes (including inside `cn()`
  and `cva()`) and Biome has no stable equivalent.
- **Vendored components are exempted via a scoped `overrides` block**, not a
  global rule change. 13 rules that fire on shadcn's registry-generated shapes
  are switched off for `src/components/ui/**` and `src/hooks/use-mobile.ts` only
  — first-party code is still covered by every one of them, so do not lift those
  exemptions to a wider glob. Biome's `recommended` preset is a broader surface
  than the old ESLint config, which is why 13 rules are listed rather than 2.
- **Prettier**: no semicolons, double quotes, 2-space indent, 80 columns, ES5
  trailing commas. `prettier-plugin-tailwindcss` sorts Tailwind classes and is
  configured to also sort inside `cn()` and `cva()` calls, so run
  `bun run format` after editing class strings. `src/components/ui/` is in
  `.prettierignore` — formatting it would rewrite 20 vendored files and break
  their byte-identity with the registry.

## Theming

`src/components/theme-provider.tsx` owns light/dark/system state, persists it to
`localStorage` under `theme`, syncs across tabs via the `storage` event, and
binds a bare **`d`** keypress as a dark-mode toggle (ignored inside inputs,
textareas, selects, and contenteditable). If you add a component with its own
keyboard handling, check it does not collide with that binding. `useTheme()`
throws outside the provider, which wraps `<App />` in `src/main.tsx`.
