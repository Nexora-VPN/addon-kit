# Nexora addon kit

What every [Nexora](https://nexora-panel.org) addon would otherwise write
again. An addon is a separate program — its own container or service, its own
database — that talks to the Nexora panel over the network only: a scoped API
token, signed webhook events, and the manifest that says what it needs.

| Package | What it does |
| --- | --- |
| [`manifest`](manifest) | The manifest (`nexora-addon.json`), its validation, signature and the setup body — the same code the panel validates with. Spec: [SPEC.md](SPEC.md) |
| [`addon`](addon) | The running half: serves the manifest, takes the credentials at registration (claim code), verifies the panel's event deliveries, answers the health check, reads the install's answers (`NEXORA_OPT_*`) |
| [`panel`](panel) | A small client for the panel's `/api/v1` with the addon's token, idempotency keys and a 429 wait |
| [`cmd/nexora-addon`](cmd/nexora-addon) | `check`, `keygen`, `sign` and `verify` a manifest |

```go
raw, _ := os.ReadFile("nexora-addon.json")
a, err := addon.New(addon.Config{Manifest: raw, DataDir: "data"}.FromEnv())
if err != nil { log.Fatal(err) }
a.OnEvent(func(e addon.Event) { log.Printf("%s %s", e.Event, e.Data) })
mux := http.NewServeMux()
a.Mount(mux)
log.Fatal(http.ListenAndServe(":8090", mux))
```

Start from [`addon-template`](https://github.com/Nexora-VPN/addon-template),
a complete minimal addon with a compose file, a binary release and an install
script. Addons are listed at [addons.nexora-panel.org](https://addons.nexora-panel.org)
as official, verified or unofficial.

Licensed under the Apache License 2.0, so an addon built on the kit may be
open or closed.
