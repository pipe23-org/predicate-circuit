# predicate-circuit

predicate-circuit is a repository holding a provisional design for a Longfellow circuit that
encodes a number of predicates. A predicate is a combination of an attribute and an opcode. A
query is a list of predicates, including opcodes, attributes, and operands. The design covers
the circuit with its harness and manifest, published queries, and the exchange between relying
party and wallet over OpenID4VP 1.0. It is experimental and unstable.

## Documentation

The design is in [DESIGN.md](DESIGN.md).

## Provenance

The design text originates in the gist
<https://gist.github.com/nathanschepers/e9d61219f67112df151b69f4c6a2c4af>, created on
2026-09-18.
The first two commits of this repository, `2912820` and `4e68f73`, are the gist's commits.

## Status

You should not rely on this design.

- The design is provisional.
- No implementation accompanies the design.
- The manifests and the published query in the design are examples.
- The design lists these open questions:
  - validation of a gadget, or of a circuit as a composition of gadgets
  - validation of a circuit's harness
  - the opcodes, predicate count, data types and limits of a useful circuit
  - the publisher of the query list, and its attachment to relying-party registration
  - the source of the consent text
  - the pseudonym construction
  - wallet behaviour when offline without the published query

## License

Undecided.
