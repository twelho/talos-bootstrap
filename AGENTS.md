# Agent instructions for developing and refactoring

NEVER leak your internal context into comments. The code is expected to be read and written by humans and agents with advanced technical ability. Code should be clear enough to be self-documenting, comments are reserved for communicating intent, and should be scoped within the context of the residing file.

Compartmentalize and modularize the code appropriately. Do not cause a tangled web of function calls across files. Use Go interfaces effectively. If a feature doesn't sit right in current architecture, consider how you could refactor the structure to better match the expectations. Avoiding duplication is a top priority. You are working with a very modern Go version, do NOT reimplement functionality that is nowadays provided by the standard library.

Do NOT stack point fixes. Be smart about cascading effects and edge cases: always fail fast and safely. For example, prefer allowlists over denylists, and always parse/validate strictly.

NO em dashes.

Keep `Makefile` and `flake.nix` in sync: if you change build flags, targets, or tooling in one, apply the equivalent change to the other.
