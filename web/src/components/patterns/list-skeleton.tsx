import { CardGrid } from "@/components/patterns/card-grid"
import { StatGrid } from "@/components/patterns/stat-tile"
import { Skeleton } from "@/components/ui/skeleton"

/** Builds [0, 1, ..., count - 1] to map over -- a single-parameter `.map()`
 * over each element's own value, matching this codebase's existing
 * skeleton-key convention (e.g. the pre-existing `[0, 1, 2].map((tile) =>
 * <Skeleton key={tile} />)` pattern) rather than an explicit index
 * parameter, which Biome's noArrayIndexKey rule flags on sight regardless
 * of whether the list can actually reorder. */
function placeholders(count: number): number[] {
  return Array.from({ length: count }, (_, position) => position)
}

/**
 * Loading placeholder for a resource list screen: a row of stat-tile
 * skeletons above a grid of card skeletons, matching the real layout's
 * proportions so the page doesn't jump when data arrives.
 */
export function ResourceListSkeleton({
  statCount,
  statGridClassName,
  cardCount,
  cardHeightClassName,
}: {
  statCount: number
  /** Overrides StatGrid's default 3-column layout, e.g. "grid-cols-2 lg:grid-cols-4". */
  statGridClassName?: string
  cardCount: number
  /** e.g. "h-32" -- card content height varies per resource type. */
  cardHeightClassName: string
}) {
  return (
    <div className="flex flex-col gap-6">
      <StatGrid className={statGridClassName}>
        {placeholders(statCount).map((tile) => (
          <Skeleton key={tile} className="h-20 rounded-4xl" />
        ))}
      </StatGrid>
      <CardGrid>
        {placeholders(cardCount).map((card) => (
          <Skeleton key={card} className={`${cardHeightClassName} rounded-4xl`} />
        ))}
      </CardGrid>
    </div>
  )
}
