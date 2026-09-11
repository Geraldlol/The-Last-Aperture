---
name: last-aperture
description: Adversarially audit code for security vulnerabilities. Fire when: the user asks for a security review, or signals a ship moment.
---

# The Last Aperture

The frontmatter above is the real Phase B defect: the `description` value carries a
second `": "`, so YAML reads it as a nested mapping, the block does not parse, and
the skill does not load. Kept as a fixture so the gate that catches it has
something to catch.
