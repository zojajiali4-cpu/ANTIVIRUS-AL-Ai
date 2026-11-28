This directory is reserved for the trained model artifact.

The Android runtime loads only `active-model.json`, format `ALAI-MV-FOREST/1`, with the exact 37-feature schema defined by `OnDeviceMlScorer.FEATURE_NAMES`. The model must be trained by `tools/train_multiview_model.py` from a licensed feature corpus that has at least 300 rows, at least 50 examples per class, at least 30 independent package/family groups, and passes the group-disjoint calibration and untouched-test FPR/recall gates.

No production model is currently installed. Do not create an empty, random, synthetic, hand-written, or label-derived model to make the UI say AI is active. The 450-row/513-feature Mendeley dataset is only a candidate until its actual CSV columns, labels, group metadata, and exact feature mapping are verified. Keep ML status `NOT_CONFIGURED` until a valid model is trained, reviewed, packaged, and independently evaluated.
