import { journeysAF } from "./journeys-a-f"
import { journeysGM } from "./journeys-g-m"
import { journeysNU } from "./journeys-n-u"
import { journeysVW } from "./journeys-v-w"
import type { Case, Suite } from "./types"

export const suites: Suite[] = [
  ...journeysAF,
  ...journeysGM,
  ...journeysNU,
  ...journeysVW,
]

/** Every case, flattened, with its suite key attached for search and report. */
export interface FlatCase extends Case {
  suiteKey: string
  suiteTitle: string
}

export const allCases: FlatCase[] = suites.flatMap((s) =>
  s.cases.map((c) => ({ ...c, suiteKey: s.key, suiteTitle: s.title }))
)

export const caseCount = allCases.length

/**
 * The source this playbook is transcribed from. Shown in the footer so a
 * tester filing a defect can quote the same document the case came from.
 */
export const source = {
  doc: "docs/VAULT_USER_ACCESS_JOURNEYS_v3.md",
  branch: "v-4.0.0",
  asOf: "2026-10-03",
}
