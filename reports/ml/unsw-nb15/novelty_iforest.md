# Detecting novel attacks: unsw-nb15 (iforest)

Hybrid = gradient-boosting classifier + isolation forest (200 trees) trained on normal traffic only. Novel attacks: leave-one-family-out: each attack family removed from training in turn.

## Held-out attack family detection at 2% false alarms

Each row: the classifier was retrained WITHOUT that family; the family is then the 'novel' attack.

| Held-out family | Classifier alone | Hybrid | Gain | Classifier AUC | Hybrid AUC |
|---|---|---|---|---|---|
| Analysis | 94.5% | 91.6% | -3.0 pts | 0.989 | 0.973 |
| Backdoor | 94.3% | 91.4% | -2.9 pts | 0.994 | 0.980 |
| DoS | 89.8% | 83.4% | -6.5 pts | 0.987 | 0.974 |
| Exploits | 71.4% | 56.0% | -15.4 pts | 0.968 | 0.934 |
| Fuzzers | 27.2% | 22.5% | -4.7 pts | 0.851 | 0.815 |
| Generic | 2.4% | 90.1% | +87.7 pts | 0.843 | 0.988 |
| Reconnaissance | 75.3% | 46.7% | -28.7 pts | 0.980 | 0.883 |
| Shellcode | 27.0% | 7.9% | -19.0 pts | 0.943 | 0.832 |
| Worms | 84.1% | 63.6% | -20.5 pts | 0.981 | 0.953 |
| **Mean over families** | **62.9%** | **61.5%** | **-1.4 pts** | | |
