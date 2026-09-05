# C-043 — clean detector mirror for model-training data admission
# The signed manifest binds an immutable source, digest, and poisoning-policy gate before training.

spec = verify_signed_manifest("training-manifest.json", APPROVED_DATA_KEYS)
rows = load_dataset(spec.immutable_uri)
verify_digest(rows, spec.sha256)
require_pass(scan_training_data(rows, policy=spec.poisoning_policy))
trainer.fit(rows)
