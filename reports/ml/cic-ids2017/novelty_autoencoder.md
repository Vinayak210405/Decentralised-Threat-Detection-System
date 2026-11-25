# Detecting novel attacks: cic-ids2017 (autoencoder)

Hybrid = gradient-boosting classifier + autoencoder reconstruction error (64-16-64) trained on normal traffic only. Novel attacks: leave-one-family-out: each attack family removed from training in turn.

## Held-out attack family detection at 2% false alarms

Each row: the classifier was retrained WITHOUT that family; the family is then the 'novel' attack.

| Held-out family | Classifier alone | Hybrid | Gain | Classifier AUC | Hybrid AUC |
|---|---|---|---|---|---|
| DoS | 31.2% | 77.1% | +46.0 pts | 0.891 | 0.981 |
| Probe | 18.9% | 21.1% | +2.3 pts | 0.939 | 0.945 |
| BruteForce | 87.7% | 98.7% | +10.9 pts | 0.991 | 0.992 |
| WebAttack | 87.2% | 86.9% | -0.2 pts | 0.989 | 0.989 |
| Botnet | 0.8% | 4.9% | +4.1 pts | 0.798 | 0.707 |
| **Mean over families** | **45.1%** | **57.8%** | **+12.6 pts** | | |
