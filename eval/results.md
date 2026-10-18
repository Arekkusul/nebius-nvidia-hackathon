# Eval results

Generated 2026-10-18 00:39 UTC. Models: {"fast": "nvidia/Nemotron-3_5-Lightning", "main": "nvidia/nemotron-3-super-120b-a12b", "reasoning": "nvidia/Nemotron-3-Ultra-550b-a55b"}

| Report | Behaviours | Rules | Validated | First-try pass | Attack events caught | Benign look-alikes blocked | Baseline FPs | Refine cycles | Red-team variants | Retired / corrected tests | Tokens in/out | Est. cost | Wall time |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aws_credential_abuse | 8 | 5 | 2 | 0 | 96% | 94% | 0 | 25 | 42 | 0 / 5 | 151,504/41,847 | $0.146 | 130s |
| linux_cryptominer_docker | 8 | 5 | 4 | 3 | 97% | 97% | 0 | 10 | 37 | 0 / 4 | 67,693/36,673 | $0.118 | 70s |
| lsass_dump_lateral_movement | 10 | 5 | 1 | 1 | 96% | 80% | 0 | 24 | 38 | 0 / 0 | 129,676/38,377 | $0.135 | 71s |
| macro_loader_campaign | 7 | 5 | 4 | 4 | 100% | 97% | 0 | 8 | 36 | 0 / 0 | 70,864/50,561 | $0.154 | 88s |
| ransomware_affiliate_intrusion | 8 | 5 | 2 | 2 | 90% | 100% | 0 | 22 | 36 | 0 / 0 | 126,546/51,290 | $0.171 | 93s |
| **Total** | 41 | 25 | 13 (52%) | 10 | | | 0 | 89 | 189 | 0 / 9 | 546,283/218,748 | $0.724 | 451s |
