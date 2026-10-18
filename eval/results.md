# Eval results

Generated 2026-10-18 00:46 UTC. Models: {"fast": "nvidia/Nemotron-3_5-Lightning", "main": "nvidia/nemotron-3-super-120b-a12b", "reasoning": "nvidia/Nemotron-3-Ultra-550b-a55b"}

| Report | Behaviours | Rules | Validated | First-try pass | Attack events caught | Benign look-alikes blocked | Baseline FPs | Refine cycles | Red-team variants | Retired / corrected tests | Tokens in/out | Est. cost | Wall time |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aws_credential_abuse | 8 | 5 | 2 | 1 | 95% | 76% | 0 | 21 | 28 | 0 / 0 | 120,076/30,161 | $0.099 | 72s |
| linux_cryptominer_docker | 10 | 5 | 4 | 1 | 92% | 100% | 0 | 17 | 39 | 0 / 0 | 103,709/39,420 | $0.132 | 70s |
| lsass_dump_lateral_movement | 8 | 5 | 2 | 0 | 92% | 87% | 0 | 23 | 40 | 0 / 0 | 138,449/53,912 | $0.183 | 102s |
| macro_loader_campaign | 7 | 5 | 2 | 2 | 68% | 100% | 0 | 21 | 41 | 0 / 0 | 140,470/53,718 | $0.180 | 93s |
| ransomware_affiliate_intrusion | 9 | 5 | 5 | 5 | 100% | 100% | 0 | 6 | 39 | 0 / 0 | 55,858/42,549 | $0.133 | 70s |
| **Total** | 42 | 25 | 15 (60%) | 9 | | | 0 | 88 | 187 | 0 / 0 | 558,562/219,760 | $0.728 | 407s |
