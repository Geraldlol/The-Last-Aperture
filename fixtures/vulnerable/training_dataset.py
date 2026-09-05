# V-023 — ai-model-and-mlops-security / training-data-provenance-and-integrity / Medium / CWE-345
# Inert detector fixture: the moving dataset is trusted by the trainer without immutable identity or integrity verification.

TRAINING_URI = os.getenv("TRAINING_URI", "s3://fraud-data/latest/")
rows = load_dataset(TRAINING_URI)
trainer.fit(rows)
