import { openEntity, queryEntities, type SelectItem } from '@/lib/fibery';
import type { Dataset, EntityRef } from './model';

const P = 'Petri Human View/';
const PAGE_SIZE = 200;
const MAX_PAGES = 25;
type Raw = Record<string, unknown>;
const obj = (v: unknown): Raw => v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Raw : {};
const text = (v: unknown): string => typeof v === 'string' ? v : '';
const id = (v: unknown): string | null => text(obj(v)['fibery/id']) || null;
const refs = (v: unknown): string[] => Array.isArray(v) ? v.flatMap(x => id(x) ? [id(x)!] : []) : [];
const option = (v: unknown): string => text(obj(v)['enum/name']);
const docSecret = (r: Raw): string | null => text(obj(r[P + 'Description'])['Collaboration~Documents/secret']) || null;
const single = (field: string, fields: string[] = ['fibery/id']): SelectItem => ({ [field]: fields });
const many = (field: string): SelectItem => ({ [field]: { 'q/select': ['fibery/id'], 'q/limit': 3001 } });
const common: SelectItem[] = ['fibery/id', 'fibery/public-id', P + 'Name'];
const doc = single(P + 'Description', ['Collaboration~Documents/secret']);
const base = (r: Raw, type: string, keyField: string): EntityRef => ({
  id: text(r['fibery/id']), publicId: text(r['fibery/public-id']), type,
  name: text(r[P + 'Name']), key: text(r[P + keyField]),
});

async function readAll(type: string, fields: SelectItem[]): Promise<Raw[]> {
  const all = new Map<string, Raw>();
  // Explicit bounded pages keep refreshes predictable; fail visibly rather than silently truncate.
  for (let page = 0; page < MAX_PAGES; page++) {
    const rows = await queryEntities<Raw>({ type, fields, limit: PAGE_SIZE, offset: page * PAGE_SIZE,
      orderBy: { field: 'fibery/id', direction: 'asc' } });
    for (const row of rows) all.set(text(row['fibery/id']), row);
    if (rows.length < PAGE_SIZE) return [...all.values()];
  }
  throw new Error(`Слишком много записей в ${type}: достигнут предел ${PAGE_SIZE * MAX_PAGES}. Уточните область просмотра.`);
}

export async function loadDataset(): Promise<Dataset> {
  const [specs, plans, facts, decisions, evidence] = await Promise.all([
    readAll(P + 'Spec', [...common, P + 'Ключ', P + 'Состояние реализации', P + 'Состояние проверки', P + 'Состояние приёмки',
      single(P + 'Текущая версия ожиданий'), many(P + 'Зависит от спек')]),
    readAll(P + 'PlanVersion', [...common, P + 'Ключ версии', P + 'Номер версии', single(P + 'Спека'),
      single(P + 'Заменяет версию'), single(P + 'Решение об изменении'), doc]),
    readAll(P + 'WorkNode', [...common, P + 'Ключ узла', P + 'Когда произошло', single(P + 'Спека'),
      single(P + 'Версия ожиданий на момент работы'), single(P + 'Тип факта', ['enum/name']),
      single('workflow/state', ['enum/name']), many(P + 'Предыдущие фактические узлы'), many(P + 'Причины этого узла'),
      many(P + 'Доказательства'), doc]),
    readAll(P + 'Decision', [...common, P + 'Ключ решения', single('workflow/state', ['enum/name']),
      many(P + 'Затронутые спеки'), many(P + 'Факты из которых возник вопрос'), many(P + 'Основания решения')]),
    readAll(P + 'Evidence', [...common, P + 'Ключ доказательства', P + 'URL источника', P + 'Наблюдалось нативное исполнение',
      single(P + 'Вид источника', ['enum/name']), single(P + 'Результат проверки', ['enum/name']), single(P + 'Платформа', ['enum/name'])]),
  ]);
  for (const [rows, key] of [[specs, 'Ключ'], [plans, 'Ключ версии'], [facts, 'Ключ узла'],
    [decisions, 'Ключ решения'], [evidence, 'Ключ доказательства']] as const) {
    rows.sort((a, b) => text(a[P + key]).localeCompare(text(b[P + key])));
  }
  return {
    specs: specs.map(r => ({ ...base(r, P + 'Spec', 'Ключ'),
      implementation: text(r[P + 'Состояние реализации']), verification: text(r[P + 'Состояние проверки']),
      acceptance: text(r[P + 'Состояние приёмки']), currentPlanId: id(r[P + 'Текущая версия ожиданий']), dependencyIds: refs(r[P + 'Зависит от спек']) })),
    plans: plans.map(r => ({ ...base(r, P + 'PlanVersion', 'Ключ версии'), specId: id(r[P + 'Спека']),
      version: Number(r[P + 'Номер версии']) || 0, supersedesId: id(r[P + 'Заменяет версию']),
      decisionId: id(r[P + 'Решение об изменении']), documentSecret: docSecret(r) })),
    facts: facts.map(r => ({ ...base(r, P + 'WorkNode', 'Ключ узла'), specId: id(r[P + 'Спека']), planId: id(r[P + 'Версия ожиданий на момент работы']),
      kind: option(r[P + 'Тип факта']), state: option(r['workflow/state']), predecessorIds: refs(r[P + 'Предыдущие фактические узлы']),
      causeIds: refs(r[P + 'Причины этого узла']), evidenceIds: refs(r[P + 'Доказательства']), documentSecret: docSecret(r),
      occurredAt: text(r[P + 'Когда произошло']) || null })),
    decisions: decisions.map(r => ({ ...base(r, P + 'Decision', 'Ключ решения'), state: option(r['workflow/state']),
      specIds: refs(r[P + 'Затронутые спеки']), contextIds: refs(r[P + 'Факты из которых возник вопрос']), evidenceIds: refs(r[P + 'Основания решения']) })),
    evidence: evidence.map(r => ({ ...base(r, P + 'Evidence', 'Ключ доказательства'), kind: option(r[P + 'Вид источника']),
      status: option(r[P + 'Результат проверки']), platform: option(r[P + 'Платформа']), url: text(r[P + 'URL источника']),
      native: r[P + 'Наблюдалось нативное исполнение'] === true })),
  };
}

export async function openRecord(ref: EntityRef): Promise<void> {
  if (!ref.publicId) throw new Error(`Нет public ID для ${ref.key || ref.name}`);
  await openEntity({ type: ref.type, publicId: ref.publicId });
}
