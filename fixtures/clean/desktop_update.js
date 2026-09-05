// C-051 — clean detector mirror for desktop update admission
// Approved channel, signed metadata, version floor, and exact package digest precede staging.

feed = updatePolicy.requireApprovedChannel(settings.channel)
release = verifySignedUpdateMetadata(feed, TRUSTED_DESKTOP_RELEASE_KEYS)
requireVersionAboveFloor(release.securityVersion)
autoUpdater.checkForUpdates({ expectedDigest: release.packageSha256 })
