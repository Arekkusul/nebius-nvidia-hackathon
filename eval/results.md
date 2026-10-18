# Eval results

Generated 2026-10-18 00:28 UTC. Models: {"fast": "nvidia/Nemotron-3_5-Lightning", "main": "nvidia/nemotron-3-super-120b-a12b", "reasoning": "nvidia/Nemotron-3-Ultra-550b-a55b"}

| Report | Behaviours | Rules | Validated | First-try pass | Attack events caught | Benign look-alikes blocked | Baseline FPs | Refine cycles | Red-team variants | Retired / corrected tests | Tokens in/out | Est. cost | Wall time |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aws_credential_abuse | 8 | 5 | 2 | 2 | 77% | 86% | 0 | 19 | 41 | 0 / 0 | 125,096/44,984 | $0.155 | 135s |
| linux_cryptominer_docker | 9 | 5 | 4 | 2 | 100% | 96% | 0 | 12 | 35 | 0 / 0 | 84,903/37,908 | $0.124 | 73s |
| lsass_dump_lateral_movement | 9 | 5 | 2 | 2 | 63% | 97% | 0 | 22 | 43 | 0 / 0 | 146,117/40,144 | $0.144 | 74s |
| macro_loader_campaign | 7 | 5 | 4 | 3 | 91% | 100% | 0 | 11 | 31 | 4 / 1 | 90,926/48,805 | $0.158 | 106s |
| ransomware_affiliate_intrusion | 10 | 5 | 2 | 4 | 92% | 93% | 0 | 14 | 39 | 0 / 0 | 96,759/34,816 | $0.121 | 74s |
| **Total** | 43 | 25 | 14 (56%) | 13 | | | 0 | 78 | 189 | 4 / 1 | 543,801/206,657 | $0.702 | 463s |
