# C-024 — clean fixture. Expected findings at Low or above: ZERO.
#
# Why this pattern-matches as vulnerable:
#   `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, a hardcoded `SECRET_KEY`, and a
#   comment saying the real one comes from somewhere else. Four of
#   ai-generated-code's §0 sweeps (A3, A12, A13) and web-and-api's verbose-error
#   row all fire on this file.
#
# Why it is not a finding:
#   1. THE DEPLOYMENT DOES NOT SELECT THIS MODULE. Establish it from the artifact
#      rather than from the filename: the container's start command is
#      `gunicorn app.wsgi --config gunicorn.conf.py`, `app/wsgi.py` sets
#      `DJANGO_SETTINGS_MODULE` to `app.settings.production` with no environment
#      fallback, and this module is imported by exactly one thing — `manage.py`'s
#      local default — which the image does not run. That chain is quoted in the
#      module docstring so a reader does not have to take the path on trust.
#   2. THE INVERSE TRAP IS DELIBERATELY ABSENT, because it is the more common
#      shape and it is NOT a false positive: there is no
#      `DEBUG = os.environ.get("DEBUG", True)` anywhere here. Every boolean is a
#      literal, so nothing is reachable in production by omission.
#   3. THE COMMENT ABOUT THE SECRET IS TRUE, and the deployment configuration that
#      makes it true is in this checkout at `app/settings/production.py`, which
#      reads the value from the secret manager with no default. A comment
#      describing a deployment split is not an admission when the split exists.
#   4. `strict = False` here is a CSV parser option, not a security control. Name
#      the control a flag governs and the property lost, or there is no finding —
#      and this flag governs whether a short row raises or pads.
#
# False-positive entries exercised:
#   ai-generated-code (5)   `debug=True` in a path the deployment does not select
#   ai-generated-code (10)  a comment that describes a deployment split
#   ai-generated-code (11)  a `strict: false` that is not a security control
#   ai-generated-code (3)   MD5 in application code — the ETag helper at the end

"""Local development settings.

SELECTED BY: manage.py only (`os.environ.setdefault("DJANGO_SETTINGS_MODULE",
"app.settings.dev")`, manage.py line 8).

NOT SELECTED BY THE DEPLOYED ARTIFACT. The chain, so it can be checked:
  Dockerfile        CMD ["gunicorn", "app.wsgi", "--config", "gunicorn.conf.py"]
  app/wsgi.py:6     os.environ["DJANGO_SETTINGS_MODULE"] = "app.settings.production"
                    (assignment, not setdefault — an injected value cannot win)
  gunicorn.conf.py  no `raw_env` entry for DJANGO_SETTINGS_MODULE

Nothing in the image imports this module.
"""

import hashlib

from .base import *  # noqa: F401,F403

# Literals, not environment reads. There is no permissive default to inherit.
DEBUG = True
ALLOWED_HOSTS = ["*"]

# Fixed, published, and worthless: it signs cookies for a database that lives in
# a throwaway container. In the deployed configuration this value is read from the
# secret manager with no default — see app/settings/production.py, which does
# `SECRET_KEY = secrets_client.get("django-secret-key")` and raises if it is
# missing. That is the deployment split this comment describes, and it exists.
SECRET_KEY = "dev-only-not-a-secret-0000000000000000"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/tmp/dev.sqlite3",
    }
}

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# A CSV parser option. `strict` here decides whether a row with fewer columns
# than the header raises or is padded with None. It governs no authentication, no
# authorization, no encoding and no transport property, so there is no control to
# name and no property that is lost.
IMPORT_CSV_OPTIONS = {
    "delimiter": ",",
    "strict": False,
    "skip_blank_lines": True,
}


def static_asset_etag(path: str, body: bytes) -> str:
    """Weak validator for the dev static server.

    MD5 over the asset bytes. No secret, no authorization decision downstream, and
    the consequence of a collision is a stale asset in a development browser.
    """
    return 'W/"%s"' % hashlib.md5(body, usedforsecurity=False).hexdigest()
