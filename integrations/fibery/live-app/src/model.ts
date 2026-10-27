export type EntityRef = { id: string; publicId: string; type: string; name: string; key: string };
export type Spec = EntityRef & {
  implementation: string; verification: string; acceptance: string;
  currentPlanId: string | null; dependencyIds: string[];
};
export type Plan = EntityRef & {
  specId: string | null; version: number; supersedesId: string | null;
  decisionId: string | null; documentSecret: string | null;
};
export type Fact = EntityRef & {
  specId: string | null; planId: string | null; kind: string; state: string;
  predecessorIds: string[]; causeIds: string[]; evidenceIds: string[];
  documentSecret: string | null; occurredAt: string | null;
};
export type Decision = EntityRef & {
  specIds: string[]; contextIds: string[]; evidenceIds: string[]; state: string;
};
export type Evidence = EntityRef & {
  kind: string; status: string; platform: string; url: string; native: boolean;
};
export type Dataset = { specs: Spec[]; plans: Plan[]; facts: Fact[]; decisions: Decision[]; evidence: Evidence[] };
