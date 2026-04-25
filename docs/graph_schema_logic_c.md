# C Graph Schema Construction Logic (Node-Client Edition)

Этот документ описывает целевую и текущую логику построения интерактивного
графа для C/Node-сценария в SmartGraphical.

## Scope and relation to other docs

- This file defines C/Node target schema and best practices.
- Implemented current behavior is documented in `docs/graph_schema_logic.md`.
- If C payload fields become implemented, mirror them into the base doc in the same change.

## 0. Implementation status (важно)

- **Реализовано сейчас (общий движок графа):**
  - построение графа из `NormalizedAuditModel` через
    `smartgraphical/services/serializers.py::model_graph_to_dict`,
  - базовые группы узлов (`type`, `function`, `state`, `external`),
  - обязательная гарантия: у каждого ребра существующие endpoints.
- **Реализовано сейчас для Solidity сверх базового:** `event`, `modifier`, rings,
  `source_body`.
- **План для C/Node:** tile/workspace/syscall-специфичные группы и richer metadata
  из этого документа.

- **Реализовано в текущем инкременте (C payload через serializer):**
  - `graph_schema_version: "1.0"` на верхнем уровне graph payload,
  - контракт обязательных полей нормализуется на выдаче:
    - node: `id`, `group`, `label`,
    - edge: `id`, `source`, `target`, `kind`,
  - C-profile канонизация групп/типов с alias-совместимостью:
    - `type -> tile`,
    - `state -> workspace`,
    - `function_to_system -> function_to_syscall`,
  - stable IDs для C-profile на выдаче:
    - `tile:<tile_name>`,
    - `function:<normalized_path>.<function_name>[.<collision_suffix>]`,
    - `workspace:<workspace_name>`,
    - `syscall:<syscall_name>`,
    - `external:<class>:<symbol>`,
  - unresolved fallback классифицируется в `external`:
    - `unresolved_fnptr`,
    - `unresolved_syscall`,
    - `unresolved_lib`,
    - `unresolved_symbol`,
  - разделение fact/heuristic на уровне edge payload:
    - `pointer_flow` помечается как `is_heuristic: true`, `confidence: "heuristic"`,
    - прочие текущие C-edge kinds получают `is_heuristic: false`, `confidence: "high"`,
  - pre-emit validation в serializer:
    - фильтрация пустых/дублирующихся `node.id` и `edge.id`,
    - удаление ребер с несуществующими endpoint,
    - разрыв циклов в `parent`-цепочке,
    - для неизвестных C `group/kind` добавляются
      `experimental_group`/`experimental_kind`.

Примечание: в текущей кодовой базе рабочий C-адаптер — `c_base`. Термин
`c_solana_node` здесь используется как целевое доменное направление.
Часть C/Node контракта в этом инкременте реализована на уровне сериализации
payload (без расширения dataclass-модели `NormalizedCallEdge` новыми полями).

## 1. Сквозной поток данных (End-to-end flow)

1. Исходный код C анализируется адаптером (`c_base`, в перспективе
   расширенным до `c_solana_node`-профиля).
2. Адаптер строит `NormalizedAuditModel`:
   - units исполнения (tiles/process groups),
   - функции,
   - сущности памяти,
   - вызовы и связи.
3. Модель сериализуется в JSON-пакет для фронтенда (Cytoscape).
4. UI рендерит узлы/ребра и панель деталей.

## 2. Schema contract (v1)

### 2.1 Обязательные поля

- **Node (обязательно):** `id`, `group`, `label`
- **Edge (обязательно):** `id`, `source`, `target`, `kind`

### 2.2 Опциональные поля (по мере зрелости адаптера)

- node: `parent`, `type_name`, `source_body`, `concurrency_risk`,
  `storage_access`, `instruction_type`, `cross_tile`, `sandbox_policy`
- edge: `label`, `confidence`, `evidence_ref`, `is_heuristic`

### 2.3 Версионирование схемы

Рекомендуемый верхнеуровневый атрибут:

- `graph_schema_version: "1.x"`

Правила совместимости:

1. Новые поля добавляются как optional.
2. Удаление/переименование обязательного поля — только через major bump.
3. Неизвестные поля должны игнорироваться фронтендом, а не ломать рендер.

## 3. Структура графа (целевая для C/Node)

### 3.1 Группы узлов (Node groups)

- `tile`: составной родительский узел процесса/потока (`quic`, `verify`, `bank`).
- `function`: исполняемые функции внутри tile/библиотек.
- `workspace`: именованные регионы памяти (`mcache`, `dcache`, `funk`).
- `global_state`: глобальные переменные/статические структуры.
- `syscall`: системные вызовы, проходящие через sandbox policy.
- `external`: внешние зависимости и unresolved-цели.

### 3.2 Стабильные идентификаторы (Stable IDs)

Идентификаторы должны быть детерминированы и collision-safe:

- `tile:<tile_name>`
- `function:<normalized_path>.<function_name>[.<signature_hash>]`
- `workspace:<workspace_name>`
- `syscall:<syscall_name>`
- `external:<class>:<symbol>`

Рекомендуется:

- нормализовать путь (от repo root),
- для потенциальных коллизий добавлять `signature_hash`.

## 4. Семантика ребер (`kind`)

Минимально документируемый набор:

- `function_to_function`: обычный call graph.
- `function_to_workspace`: доступ к разделяемой памяти.
- `tile_to_tile`: IPC/канальные переходы.
- `function_to_syscall`: системный вызов.
- `pointer_flow`: эвристический поток указателей.

Для каждого `kind` в реализации желательно фиксировать:

1. направление (`source -> target`),
2. источник факта (парсер/эвристика),
3. confidence (`high`, `medium`, `heuristic`),
4. допустимые false positives/negatives.

## 5. Разделение фактов и эвристик

Best practice:

- **Observed fact:** прямой синтаксический сигнал (например, явный вызов).
- **Derived heuristic:** доменное предположение (например, pointer flow risk).

Для эвристик добавлять `is_heuristic: true` и `confidence`.

## 6. Специфика нодового клиента (Sandbox / Capability view)

Целевой слой поверх базового графа:

1. сбор разрешенных syscalls/ресурсов per tile,
2. визуальные маркеры нарушений policy,
3. отдельная подсветка cross-tile путей и рискованных memory access pattern.

## 7. Frontend rendering best practices

### 7.1 Визуальные конвенции

- Tile как compound контейнер.
- Function как основной узел исполнения.
- Workspace и Syscall как явные boundary/state ресурсы.
- Разные `kind` ребер различаются цветом и line-style.

### 7.2 Поведение при клике

- Tile: policy summary (sandbox/resources).
- Function: код + вовлеченные workspace/syscall + risk markers.
- Workspace: все читатели/писатели (race inspection).

## 8. Fallback и unresolved policy

Если endpoint не сопоставлен, создается `external:<class>:<symbol>`.

Рекомендуемая классификация `class`:

- `unresolved_fnptr`
- `unresolved_syscall`
- `unresolved_lib`
- `unresolved_symbol`

Не удалять такие ребра: это важно для security triage.

## 9. Валидация и QA

Перед отдачей payload:

1. `id` узлов уникальны.
2. Каждый `edge.source/edge.target` существует в node set.
3. Нет циклов в `parent`-цепочке compound-узлов.
4. `group/kind` из контролируемого словаря (или помечены как experimental).

Рекомендуемые тесты:

- contract tests схемы (shape tests),
- golden test на representative C-file/module,
- regression test для unresolved и pointer-flow эвристик.

## 10. Масштаб и деградация UX

Для крупных графов (например, >10k узлов) рекомендуется:

- кластеризация по tile/module,
- lazy expansion узлов,
- hard limit на auto-layout iterations,
- режим "summary-first" перед full graph.

Это предотвращает зависания UI и делает triage воспроизводимым.

