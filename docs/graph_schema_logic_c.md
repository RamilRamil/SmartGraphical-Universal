# C Graph Schema Construction Logic (Node-Client Edition)

Этот документ описывает целевую и текущую логику построения интерактивного
графа для C/Node-сценария в SmartGraphical.

## Scope and relation to other docs

- This file defines C/Node target schema and best practices.
- Implemented current behavior is documented in `docs/graph_schema_logic.md`.
- If C payload fields become implemented, mirror them into the base doc in the same change.

## 0. Implementation status (важно)

### 0.1 Сводная таблица: `c_base` и граф (по состоянию репозитория)

| Элемент | Заполняет `c_base` | Примечание |
|--------|---------------------|------------|
| `NormalizedType` (1 на TU) | да | `kind=translation_unit`, имя = stem файла |
| `NormalizedFunction` | да | regex по сигнатуре; `body`, `inputs`, `exploration_statements` |
| `state_entities` / узлы `struct` | да | тег по `struct Name {` |
| `state_entities` / `typedef_struct` | да | `typedef struct … } Alias;`; при `Alias ==` тегу `struct` узел typedef не дублируется |
| `state_entities` / `include_template` | да | `#include "…​.c"` и `#include <…​.c>` |
| Имена `inc:*` при коллизии basename | да | второй и далее путь: `inc:base~<sha256[:8]>` |
| `call_edges` `function_to_function` | да | токены `ident(` в теле |
| `call_edges` `function_to_workspace` | да | текст параметров + тело: `struct T`; для голого `T*` — только если `T` не в deny-list примитивоподобных имён (`int`, `uint32_t`, …); цели — теги `struct` и имена `typedef_struct` |
| `findings_data.function_facts` / `struct_field_access_hints` | да | опционально в нормализованной модели: эвристика `param->field` при привязке параметра к известному `struct`/`typedef_struct`; через `model_graph_to_dict` в payload графа **не** экспортируется (остаётся для правил и других потребителей модели) |
| `call_edges` `function_to_include_template` | да | **одно** ребро на пару (узел TU/tile, `inc:*`); в `NormalizedCallEdge.source_name` сентинел `__tu_include_anchor__`; на графе источник — id tile |
| `exploration_hints` в JSON графа | да | сериализатор, `language=c`; см. ниже расширенные поля |
| `exploration_hints` / `node_count`, `edge_count` | да | после нормализации payload |
| `exploration_hints` / предупреждение о размере | да | при превышении `C_GRAPH_NODE_WARN_THRESHOLD` или `C_GRAPH_EDGE_WARN_THRESHOLD` — `large_graph_warning`, `large_graph_note` |
| Узел `function` / `calls_include_template` (C JSON) | да | `true`, если предок-tile имеет исходящее `function_to_include_template` |
| Узел `function` / `heuristic_callees_ordered` | да (C JSON) | порядок имён вызовов из `function_facts[stem.fn].dataflow.ordered_calls` |
| `external:<class>:<symbol>` эвристика класса | да | `model_graph_to_dict`: `_external_class_for_unresolved` — префиксы `SYS_`, `__NR_` → `unresolved_syscall`; `fd_`, `pthread_`, `epoll_`, `ioctl` / `ioctl_*` → `unresolved_lib`; плюс прежние правила (`syscall` в имени, fnptr, `::`/`.` и т.д.) |
| Edge `is_heuristic` / `confidence` | да | для C: `function_to_function`, `function_to_workspace`, `function_to_include_template`, `pointer_flow` = heuristic |
| Препроцессор / макросы | нет | |
| `tile` / `ipc` как в domain-доке | частично | TU мапится на один compound (`type`→`tile`) |

Детали сериализатора: `smartgraphical/services/serializers.py` (`model_graph_to_dict`, `_is_c_profile_graph`).  
Общая схема UI: `docs/graph_schema_logic.md`.

### 0.2 Исторический блок (архитектура)

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
  - для неразрешённых вызовов **`external:<class>:<symbol>`** класс `class`
    уточняется эвристикой по имени символа (префиксы `SYS_`, `__NR_`, `fd_`,
    `pthread_`, `epoll_`, `ioctl` и др.; см. `_external_class_for_unresolved` в
    `serializers.py`),
  - разделение fact/heuristic на уровне edge payload (C-profile):
    - виды `function_to_function`, `function_to_workspace`,
      `function_to_include_template`, `pointer_flow` -> `is_heuristic: true`,
      `confidence: "heuristic"`,
    - остальные известные C `kind` из allowlist -> `confidence: "high"` (если появятся),
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
  `storage_access`, `instruction_type`, `cross_tile`, `sandbox_policy`,
  **`heuristic_callees_ordered`** (C-profile, function nodes)
- edge: `label`, `confidence`, `evidence_ref`, `is_heuristic`
- graph payload (верхний уровень, C-profile): **`exploration_hints`** с
  `call_edges_are_heuristic`, `call_edge_count`, **`node_count`**, **`edge_count`**,
  опционально **`large_graph_warning`**, **`large_graph_note`**, поле `note`

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
- `function_to_workspace`: в `c_base` — эвристика использования агрегатного типа: подпись и тело проверяются на `struct T` и на голый `T*` (см. deny-list примитивоподобных имён в адаптере); узлы-цели — сущности `struct` и `typedef_struct`.
- `function_to_include_template`: в `c_base` — **одно** ребро на каждый узел `inc:*` от **tile** (TU); в модели `source_name` = `__tu_include_anchor__`; полностью эвристично.
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

