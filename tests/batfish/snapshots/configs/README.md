Batfish reads vendor-style configs from here. In CI a small step renders the
FRR/nftables intent into Batfish-parseable stubs. For local runs, place
`show running-config` exports here and re-run `make batfish`.
