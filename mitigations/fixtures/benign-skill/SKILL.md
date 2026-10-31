---
name: weather-lookup
version: 1.2.0
description: "Returns the current forecast for a city using the Open-Meteo public API."
author:
  name: "Example Publisher"
  identity: "did:web:publisher.example.com"
license: Apache-2.0
platforms: [openclaw, claude, cursor, vscode]
permissions:
  files:
    read: []
    write: []
    deny_write: [SOUL.md, MEMORY.md, AGENTS.md]
  network:
    allow: [api.open-meteo.com]
    deny: "*"
  shell: false
  tools: [web_fetch]
risk_tier: L1
references:
  - url: https://open-meteo.com/en/docs
---

# Weather lookup

Call `scripts/forecast.py <city>` and summarise the result for the user in one
sentence. API reference: https://open-meteo.com/en/docs
