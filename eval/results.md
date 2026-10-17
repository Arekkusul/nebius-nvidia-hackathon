# Eval results

Generated 2026-10-17 08:10 UTC. Models: {"fast": "nvidia/Nemotron-3_5-Lightning", "main": "nvidia/nemotron-3-super-120b-a12b", "reasoning": "nvidia/Nemotron-3-Ultra-550b-a55b"}

| Report | Behaviours | Rules | Validated | First-try pass | Attack events caught | Benign look-alikes blocked | Baseline FPs | Refine cycles | Red-team variants | Tokens in/out | Est. cost | Wall time |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aws_credential_abuse | 8 | 5 | 3 | 1 | 79% | 94% | 0 | 17 | 43 | 83,020/37,047 | $0.120 | 78s |
| linux_cryptominer_docker | 10 | 5 | 3 | 2 | 87% | 100% | 0 | 14 | 40 | 73,247/44,753 | $0.136 | 80s |
| lsass_dump_lateral_movement | 10 | 5 | 2 | 2 | 75% | 96% | 0 | 16 | 37 | 79,015/43,524 | $0.136 | 94s |
| macro_loader_campaign | 7 | 5 | 1 | 1 | 75% | 100% | 0 | 22 | 42 | 106,693/44,126 | $0.140 | 80s |
| ransomware_affiliate_intrusion | 9 | 5 | 3 | 2 | 88% | 100% | 0 | 14 | 44 | 72,436/40,753 | $0.126 | 77s |
| **Total** | 44 | 25 | 12 (48%) | 8 | | | 0 | 83 | 206 | 414,411/210,203 | $0.658 | 409s |
