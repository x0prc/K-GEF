# K-GEF
Firmware Vulnerability Explorer using Knowledge Graphs

## TODO

- [ ] Add firmware unpack + ELF discovery.
- [ ] Hook in Ghidra headless and export JSON.
- [ ] Build an internal graph (firmware → binaries → functions → calls/strings/libs).
- [ ] Tag functions (network sources, memory sinks, crypto).
- [ ] Push the graph into Neo4j and set up schema/indexes.
- [ ] Implement canned security queries and expose them via CLI.
- [ ] Test cases on real firmware, tweak heuristics.

