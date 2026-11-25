# Federated learning summary: nsl-kdd

3 simulated companies, 30 rounds, class-balanced local loss, mean ± std over seeds [1, 2, 3, 4, 5]. All numbers are % on the official test set.

| Partition / aggregation | Centralised macro-F1 | Federated macro-F1 | Local-only macro-F1 (mean of companies) | Federated detection | Local-only detection | Federated false alarms | Recall on never-seen categories: local → federated |
|---|---|---|---|---|---|---|---|
| by-attack / samples | 59.0 ± 4.4 | 49.7 ± 1.9 | 28.1 ± 0.6 | 63.9 ± 1.8 | 23.2 ± 0.9 | 3.2 ± 0.1 | 0.0 ± 0.0 → 46.8 ± 1.1 |
| by-attack / uniform | 59.0 ± 4.4 | 57.7 ± 2.4 | 28.1 ± 0.6 | 61.7 ± 0.7 | 23.2 ± 0.9 | 2.6 ± 0.2 | 0.0 ± 0.0 → 47.4 ± 0.7 |
| dirichlet / samples | 59.0 ± 4.4 | 59.2 ± 6.3 | 52.0 ± 5.7 | 67.4 ± 4.9 | 66.7 ± 4.9 | 4.2 ± 1.8 | 0.0 ± 0.0 → 58.1 ± 7.2 |
| iid / samples | 59.0 ± 4.4 | 63.8 ± 2.7 | 59.7 ± 1.7 | 71.9 ± 2.1 | 67.8 ± 1.4 | 6.9 ± 1.9 | n/a → n/a |

Partitions: **by-attack** = each company sees Normal traffic plus only its own attack categories (A: DoS+Probe, B: R2L, C: U2R); **dirichlet** = label skew with alpha=0.3; **iid** = random equal split. Aggregation: **samples** = standard FedAvg, **uniform** = equal weight per company.
