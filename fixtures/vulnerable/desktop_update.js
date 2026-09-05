// V-031 — desktop-and-thick-client-security / desktop-update-authenticity-and-rollback / Medium / CWE-494
// Inert detector fixture: an application setting chooses the update feed without signed metadata or a security floor.

autoUpdater.setFeedURL({ url: settings.updateUrl })
autoUpdater.checkForUpdates()
