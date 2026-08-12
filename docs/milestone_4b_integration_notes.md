# Milestone 4B integration notes

This PR keeps the Gecko/IE registry and Gecko outcome adapter private. It does
not publish report DTOs or alter any named browser wrapper.

Milestone 4E should replace `EngineExtractionOutcome` with the frozen shared
report core, preserving its source-level behavior: missing Firefox session
candidates remain silent, invalid existing candidates are retained with
`selected: false`, and the first valid candidate is selected. IE is registered
here but its Windows acquisition/record decoding remains owned by the existing
IE implementation; the final adapter belongs with the shared 4E contract.
