# Research: Missing VaultState storage variables

## Root cause

`ContractReader.vars` = `['string', 'uint', 'mapping', 'address', 'bytes']`.

`extract_variables` searches `line_sep + whitespace + TYPE + word_boundary`.

- `uint\b` does **not** match `uint128` or `uint256` (no word boundary after `uint`).
- Only `mapping(...)` declarations match in `VaultState.sol`, hence only `_exitRequests` and `_balances`.
- `_donatedAssets` (`uint256`), `_totalShares` (`uint128`), `_exitQueue` (`ExitQueue.History`) are skipped.

## Decision

Add regex type prefixes: `uint\d*`, `int\d*`, `bytes\d*`, `bool`, plus a secondary pass for `Type[.Type] visibility name;` storage lines.

## Alternatives

- Full Solidity AST parser: out of scope.
- Append every Solidity type keyword manually: incomplete for uintN sizes.
