import type {Fact} from "./model";

/**
 * Filters the view without changing a fact's historical plan association.
 * Context contains only immediate, explicitly recorded relations in either
 * direction. Its inclusion never assigns an unassigned fact to this spec.
 */
export function selectFactScope(
  all: readonly Fact[],
  specId: string,
  planId: string | null,
  onlyPlan: boolean,
): {primary: Fact[]; graphFacts: Fact[]} {
  const primary = all.filter(
    (fact) => fact.specId === specId && (!onlyPlan || (planId !== null && fact.planId === planId)),
  );
  const primaryIds = new Set(primary.map((fact) => fact.id));
  const referencedIds = new Set(primary.flatMap((fact) => [...fact.predecessorIds, ...fact.causeIds]));
  const context = all.filter(
    (fact) =>
      !primaryIds.has(fact.id) &&
      (referencedIds.has(fact.id) ||
        [...fact.predecessorIds, ...fact.causeIds].some((id) => primaryIds.has(id))),
  );
  return {primary, graphFacts: [...primary, ...context]};
}
