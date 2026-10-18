# Eval results

Generated 2026-10-18 00:16 UTC. Models: {"fast": "nvidia/Nemotron-3_5-Lightning", "main": "nvidia/nemotron-3-super-120b-a12b", "reasoning": "nvidia/Nemotron-3-Ultra-550b-a55b"}

| Report | Behaviours | Rules | Validated | First-try pass | Attack events caught | Benign look-alikes blocked | Baseline FPs | Refine cycles | Red-team variants | Retired | Tokens in/out | Est. cost | Wall time |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aws_credential_abuse | 6 | 5 | 2 | 3 | 100% | 83% | 0 | 15 | 40 | 0 | 76,665/38,563 | $0.125 | 68s |
| linux_cryptominer_docker | 9 | 5 | 2 | 3 | 90% | 93% | 0 | 13 | 38 | 0 | 76,945/32,893 | $0.111 | 77s |
| lsass_dump_lateral_movement | 8 | 5 | 2 | 2 | 100% | 90% | 0 | 14 | 25 | 0 | 87,865/33,280 | $0.107 | 68s |
| macro_loader_campaign | 7 | 4 | 1 | 2 | 77% | 96% | 0 | 14 | 32 | 0 | 100,341/37,346 | $0.124 | 86s |
| ransomware_affiliate_intrusion | 8 | 5 | 2 | 2 | 88% | 100% | 0 | 15 | 42 | 0 | 107,337/46,686 | $0.156 | 90s |
| **Total** | 38 | 24 | 9 (38%) | 12 | | | 0 | 71 | 177 | 0 | 449,153/188,768 | $0.623 | 390s |
