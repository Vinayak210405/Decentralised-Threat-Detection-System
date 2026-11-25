# Detecting novel attacks: nsl-kdd (autoencoder)

Hybrid = gradient-boosting classifier + autoencoder reconstruction error (64-16-64) trained on normal traffic only. Novel attacks: 17 attack types present only in the official test set (3750 rows).

## Detection of novel attacks at the same false-alarm rate

| Detector | at 1% false alarms | at 2% false alarms | at 5% false alarms | at 10% false alarms | AUC |
|---|---|---|---|---|---|
| Classifier alone | 5.2% | 5.3% | 71.0% | 75.5% | 0.881 |
| Anomaly detector alone | 39.1% | 56.1% | 75.3% | 82.6% | 0.948 |
| **Hybrid** | 5.3% | 7.7% | 80.3% | 82.9% | 0.940 |

Known attack types at the same false-alarm rates:

| Detector | at 1% | at 2% | at 5% | at 10% |
|---|---|---|---|---|
| Classifier alone | 55.3% | 70.8% | 90.7% | 91.2% |
| Hybrid | 55.4% | 72.8% | 91.1% | 91.6% |

## Deployable operating point

Thresholds set on held-out *training* normals for a 2.0% false-alarm target, then measured on the test set:

| | False alarms (test) | Novel attacks detected | Known attacks detected |
|---|---|---|---|
| Classifier alone (default threshold) | 2.8% | 32.0% | |
| Hybrid | 4.2% | 75.6% | 90.8% |

43.6% of novel attack flows were labelled `Unknown` (flagged by the anomaly detector only).

## Combination rules tried

The default was chosen after looking at this test set (and a synthetic case where a plain sum failed), so every rule tried is listed; UNSW-NB15 (leave-one-family-out) is the independent check.

| Rule | Novel @2% | Novel @5% | Novel @10% | Known @2% | Known @5% | AUC novel | AUC known |
|---|---|---|---|---|---|---|---|
| classifier only | 5.3% | 71.0% | 75.5% | 70.8% | 90.7% | 0.881 | 0.977 |
| anomaly only | 56.1% | 75.3% | 82.6% | 67.5% | 81.3% | 0.948 | 0.967 |
| max(classifier, anomaly) | 5.3% | 71.1% | 74.7% | 70.8% | 90.9% | 0.934 | 0.975 |
| sum | 7.7% | 80.3% | 82.9% | 72.8% | 91.1% | 0.934 | 0.978 |
| 0.3 x classifier + anomaly | 15.4% | 78.9% | 83.8% | 69.5% | 91.1% | 0.941 | 0.978 |
| anomaly + max(classifier, 0) (default) | 7.7% | 80.3% | 82.9% | 72.8% | 91.1% | 0.940 | 0.978 |

2.3% of normal test flows get a classifier attack probability above 0.999, so below that false-alarm rate no rule that uses the classifier can do much.

## Anomaly scorers compared

| Scorer | AUC: normal vs novel attacks | AUC: normal vs all attacks | Fit + score time |
|---|---|---|---|
| k-nearest-neighbour distance to normal traffic (k=5) | 0.935 | 0.966 | 2.3s |
| autoencoder reconstruction error (64-16-64) | 0.948 | 0.962 | 0.9s |
| isolation forest (200 trees) | 0.953 | 0.947 | 0.6s |

![curve](novelty_autoencoder_curve.png)
