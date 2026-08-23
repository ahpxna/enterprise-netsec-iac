The `configs/` directory contains a generated Cisco-IOS-format Batfish model
of the Path A campus-to-DC path. Do not edit those files directly. Run
`python scripts/render_batfish_snapshot.py` after changing
`intent/fabric.yaml`; CI rejects drift. The model includes a permitted DNS
flow and a prohibited RADIUS flow so the negative test has a positive control.
