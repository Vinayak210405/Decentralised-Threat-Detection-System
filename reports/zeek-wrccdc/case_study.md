# Case study: real Zeek logs (WRCCDC 2018)

1,021,950 real connections from 664 sources over 21 minutes of the 2018 Western Regional Collegiate Cyber Defense Competition, where a red team attacks student-defended networks. Data: Brim/Zed sample Zeek logs (CC BY-SA 4.0), not redistributed here. **No labels exist**, so sources are compared with a behavioural proxy (see `scripts/zeek_case_study.py`), not ground truth.

Connection states: SF 355,909, S0 336,963, REJ 223,175, RSTO 46,839, OTH 30,240, RSTR 25,489, S1 2,366, SHR 345 (S0 = no handshake, REJ = rejected: the footprint of mass scanning).

## Results

Benign figures exclude the 16 likely-benign sources used to calibrate the third detector, so all three are measured on the same held-out sources.

| Detector | Scanner connections flagged | Benign connections flagged | Scanners reported | Benign sources reported | Unclear sources reported |
|---|---|---|---|---|---|
| classifier, report if 5 flagged | 53.9% | 1.7% | 16 of 16 | 4 of 15 | 83 of 617 |
| classifier, report if 5 flagged and at least 20% | 53.9% | 1.7% | 13 of 16 | 0 of 15 | 21 of 617 |
| hybrid (uncalibrated), report if 5 flagged | 99.8% | 98.4% | 16 of 16 | 11 of 15 | 143 of 617 |
| hybrid (uncalibrated), report if 5 flagged and at least 20% | 99.8% | 98.4% | 16 of 16 | 7 of 15 | 138 of 617 |
| hybrid (calibrated on half the benign sources), report if 5 flagged | 100.0% | 2.1% | 16 of 16 | 10 of 15 | 145 of 617 |
| hybrid (calibrated on half the benign sources), report if 5 flagged and at least 20% | 100.0% | 2.1% | 16 of 16 | 7 of 15 | 145 of 617 |

A source is *reported* when 5 or more of its connections are flagged; scanners need only that for the consortium to learn about them, so source-level detection can be complete even when many individual scan connections look normal.

## The 15 busiest sources

| Source | Connections | Distinct targets | Failed | Proxy | Classifier flagged | Calibrated hybrid flagged |
|---|---|---|---|---|---|---|
| 10.174.251.215 | 279,014 | 10,844 | 95% | likely scanner | 166,638 | 279,014 |
| 10.47.24.81 | 162,247 | 8 | 0% | likely benign | 5,323 | 2,394 |
| 10.47.26.82 | 153,060 | 3 | 0% | likely benign | 2,571 | 2,379 |
| 10.224.110.133 | 67,320 | 10,807 | 96% | likely scanner | 36,791 | 67,320 |
| 10.218.221.240 | 52,894 | 10,888 | 95% | likely scanner | 30,993 | 52,873 |
| 10.196.136.60 | 42,505 | 10,846 | 95% | likely scanner | 24,760 | 42,500 |
| 10.128.0.207 | 40,923 | 27,081 | 99% | likely scanner | 15,536 | 40,923 |
| 10.128.0.241 | 33,361 | 2,881 | 86% | likely scanner | 3,508 | 33,361 |
| 10.164.94.120 | 26,726 | 706 | 17% | unclear | 2,849 | 26,726 |
| 10.191.2.236 | 26,406 | 9,271 | 95% | likely scanner | 16,239 | 26,400 |
| 10.219.216.224 | 25,867 | 9,179 | 96% | likely scanner | 16,483 | 25,856 |
| 10.132.229.74 | 15,847 | 10,634 | 94% | likely scanner | 9,745 | 15,835 |
| 10.239.34.35 | 13,540 | 9,027 | 94% | likely scanner | 8,541 | 13,520 |
| 10.248.202.62 | 13,190 | 8,587 | 94% | likely scanner | 8,369 | 13,186 |
| 10.128.0.213 | 8,084 | 4,031 | 99% | likely scanner | 311 | 8,084 |
