# Go: описания правил (русский)

Машиночитаемый каталог (EN): `docs/go_language_rules_catalog.json`.

**Источник:** Sigma Prime, [Go for Security Auditors: Part 1 - Syntax That Will Trip You Up](https://sigmaprime.io/blog/go-for-security-auditors-part-1/) (июнь 2026). Часть 1 из серии из трёх статей: синтаксис, типичные ловушки, тесты и pragma компилятора.

**Статус:** каталог правил **1-18**; адаптер `smartgraphical/adapters/go/adapter.py` (Spec Kit: `specs/019-go-language-rules/`).

**Группы задач.** `WeirdSyntax`: 1-6; `CommonPitfalls`: 7-11; `TestingSurface`: 12-15; `CompilerPragmas`: 16-18.

**Чеклист ревью** (из каталога): инициализация map/slice в конструкторах; pointer receiver для мутаций; bare `nil` при успехе в `error`; отмена через `ctx.Done()` в фоновых циклах; копия переменной цикла до Go 1.22; security-тесты не спрятаны за build tags; редкие `//go:*` pragma обоснованы.

---

## Часть A. Неочевидный синтаксис (`WeirdSyntax`)

### 1 — `sparse_array_initialization`

**Блок:** weird_syntax. **Серьёзность:** medium.

**Суть:** литерал массива с явными индексами (`3: 400`) автоматически заполняет пропуски нулями. Ошибка в индексах в wire/crypto-коде даёт тихий padding.

**Срабатывание:** composite literal с ключами индексов в `[]byte` или числовых массивах.

**Действие:** сверить каждый индекс со спецификацией протокола; предпочитать последовательные литералы или именованные константы.

---

### 2 — `multi_param_type_sharing_obscurity`

**Блок:** weird_syntax. **Серьёзность:** info.

**Суть:** при `func verify(a, b, expected []byte)` легко не заметить, что все три параметра — слайсы байт; copy-paste может унаследовать неверный тип.

**Срабатывание:** несколько идентификаторов перед одним типом в сигнатуре.

**Действие:** перечитывать сигнатуры медленно на security-sensitive функциях сравнения/верификации.

---

### 3 — `blank_identifier_index_discard`

**Блок:** weird_syntax. **Серьёзность:** medium.

**Суть:** `for _, x := range xs` отбрасывает индекс; если логика зависит от позиции, это баг или скрытые side effects.

**Срабатывание:** `_` в range при упоминании порядка, чётности или позиционных инвариантов в теле.

**Действие:** привязать индекс и проверять его явно.

---

### 4 — `closure_loop_variable_capture`

**Блок:** weird_syntax / concurrency. **Серьёзность:** high.

**Суть:** замыкание или `go func()` внутри цикла захватывает переменную цикла по ссылке. До Go 1.22 все итерации часто видят финальное значение (классический баг «десять раз 10»).

**Срабатывание:** goroutine/defer в `for`/`range` без копии `i := i` на каждой итерации.

**Действие:** копировать переменную в теле; проверить `go.mod` и версию toolchain.

---

### 5 — `value_receiver_mutation_lost`

**Блок:** weird_syntax. **Серьёзность:** high.

**Суть:** метод с receiver `(s State)` работает с копией; мутации полей и «обновлённые» флаги безопасности исчезают.

**Срабатывание:** value receiver при присваивании полям `s` или вызове `Lock` на `s`.

**Действие:** использовать `*Type`, если метод меняет состояние или держит mutex.

---

### 6 — `unbounded_loop_missing_cancel`

**Блок:** weird_syntax / DoS. **Серьёзность:** high.

**Суть:** `for { select { ... } }` без ветки `<-ctx.Done()` не останавливается при shutdown; утечка goroutine и ёмкости.

**Срабатывание:** бесконечный цикл обслуживания HTTP, gRPC, libp2p, worker queue.

**Действие:** проследить все exit path; протащить `context` в listeners и фоновые workers.

---

## Часть B. Типичные ловушки (`CommonPitfalls`)

### 7 — `nil_map_write_panic`

**Серьёзность:** high.

**Суть:** поле `map` в struct по умолчанию `nil`; чтение OK, запись — panic. Тесты только на чтение маскируют crash в production.

**Срабатывание:** запись в map-поле без `make` в конструкторе.

**Действие:** инициализировать map в конструкторе; аудит всех map-полей config/state struct.

---

### 8 — `slice_aliasing_sensitive`

**Серьёзность:** high.

**Суть:** sub-slice разделяет backing array; `append` при наличии capacity меняет «соседей»; обнуление одного слайса не очищает копию.

**Срабатывание:** `original[1:3]` + мутация/`append` в crypto или concurrent коде.

**Действие:** явная копия через `append([]T(nil), src...)` или `copy()`; учитывать capacity при `append`.

---

### 9 — `defer_argument_eager_eval`

**Серьёзность:** medium.

**Суть:** аргументы `defer` вычисляются при регистрации, не при return. `defer log.Printf("took %v", time.Since(start))` логирует 0.

**Срабатывание:** `defer` с `time.Since`, `len` и другими вызовами, которые должны выполняться на выходе.

**Действие:** обернуть в `defer func() { ... }()`.

---

### 10 — `typed_nil_interface_return`

**Серьёзность:** high.

**Суть:** `var err *MyError = nil; return err` как `error` даёт интерфейс с типом `*MyError` и nil-значением — `err != nil` истинно.

**Срабатывание:** возврат typed nil pointer через интерфейс `error`.

**Действие:** на успехе возвращать bare `return nil`.

---

### 11 — `variable_shadowing_stale_err`

**Серьёзность:** medium.

**Суть:** `:=` в `if` затеняет внешний `err`; после неудачного type assert `fmt.Errorf("...: %w", err)` может обернуть старый или nil `err`.

**Срабатывание:** shadowing `err` или `%w` не от той ветки ошибки.

**Действие:** `go vet -shadow`; каждый wrap — от ошибки непосредственно предшествующей ветки.

---

## Часть C. Поверхность тестов (`TestingSurface`)

### 12 — `parallel_subtest_loop_capture`

**Серьёзность:** medium.

**Суть:** `t.Parallel()` в table-driven subtests без `tc := tc` (pre-1.22) гоняет последний кейс многократно.

**Срабатывание:** `for _, tc := range cases { t.Run(..., func(t *testing.T) { t.Parallel() ...}) }`.

**Действие:** копия `tc := tc`; проверить версию Go в CI.

---

### 13 — `build_tag_hidden_security_tests`

**Серьёзность:** medium.

**Суть:** `//go:build integration` или `!prod` исключает тесты из `go test` без `-tags`.

**Срабатывание:** build tags на security-relevant тестах без соответствующего CI.

**Действие:** аудит CI tag matrix; в ревью запускать `go test -tags integration`.

---

### 14 — `table_driven_missing_edge_cases`

**Серьёзность:** low.

**Суть:** большая таблица happy-path создаёт ложное ощущение покрытия; нет malformed input, границ, error paths.

**Срабатывание:** таблица только success cases у parser/auth/crypto entrypoints.

**Действие:** добавить empty, max, malformed, permission-denied; смотреть содержимое таблицы, не только форму.

---

### 15 — `external_test_package_blackbox_gap`

**Серьёзность:** info.

**Суть:** `package mypkg_test` не видит unexported API; тонкие internal invariant могут быть не покрыты.

**Срабатывание:** все тесты только black-box через `_test` suffix package.

**Действие:** искать white-box `impl_test.go` в том же package для чувствительных internals.

---

## Часть D. Pragma компилятора (`CompilerPragmas`)

### 16 — `compiler_pragma_noescape`

**Серьёзность:** critical.

**Суть:** неверный `//go:noescape` — pointer после stack frame или некорректный escape analysis (use-after-free в «безопасном» Go).

**Срабатывание:** `//go:noescape` на функциях с pointer params/returns.

**Действие:** доказать lifetime; pragma — только с обоснованием.

---

### 17 — `compiler_pragma_nosplit`

**Серьёзность:** high.

**Суть:** `//go:nosplit` запрещает рост stack; глубокая рекурсия → stack overflow вместо расширения.

**Срабатывание:** nosplit на рекурсивных или deep call chain функциях.

**Действие:** ограничить глубину stack; обычно допустимо только в runtime internals.

---

### 18 — `compiler_pragma_linkname`

**Серьёзность:** high.

**Суть:** `//go:linkname` импортирует unexported символы чужих пакетов; ломает инкапсуляцию и стабильность между релизами Go.

**Срабатывание:** директива linkname на foreign symbols.

**Действие:** высокий уровень scrutiny; предпочитать публичный API.

---

## Связанные материалы Sigma Prime

- **Part 2 (planned):** навигация по codebase, entry points (HTTP, gRPC, libp2p).
- **Part 3 (planned):** типовые уязвимости в Go (goroutine leaks, nil deref, missing nil checks).

При подключении адаптера Go: реестр `smartgraphical/adapters/go/adapter.py`, runners `smartgraphical/core/rules/go/language_rules.py`, Spec Kit `specs/019-go-language-rules/`.
