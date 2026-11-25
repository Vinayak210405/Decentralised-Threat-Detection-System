# Detecting novel attacks: unsw-nb15 (autoencoder)

Hybrid = gradient-boosting classifier + autoencoder reconstruction error (64-16-64) trained on normal traffic only. Novel attacks: leave-one-family-out: each attack family removed from training in turn.

## Held-out attack family detection at 2% false alarms

Each row: the classifier was retrained WITHOUT that family; the family is then the 'novel' attack.

| Held-out family | Classifier alone | Hybrid | Gain | Classifier AUC | Hybrid AUC |
|---|---|---|---|---|---|
| Analysis | 94.5% | 97.5% | +3.0 pts | 0.989 | 0.997 |
| Backdoor | 94.3% | 94.7% | +0.3 pts | 0.994 | 0.992 |
| DoS | 89.8% | 89.7% | -0.1 pts | 0.987 | 0.988 |
| Exploits | 71.4% | 85.6% | +14.2 pts | 0.968 | 0.982 |
| Fuzzers | 27.2% | 27.7% | +0.5 pts | 0.851 | 0.864 |
| Generic | 2.4% | 98.8% | +96.4 pts | 0.843 | 0.995 |
| Reconnaissance | 75.3% | 24.8% | -50.5 pts | 0.980 | 0.885 |
| Shellcode | 27.0% | 1.3% | -25.7 pts | 0.943 | 0.803 |
| Worms | 84.1% | 77.3% | -6.8 pts | 0.981 | 0.960 |
| **Mean over families** | **62.9%** | **66.4%** | **+3.5 pts** | | |
