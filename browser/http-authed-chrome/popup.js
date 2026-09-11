const LOOPBACK_PERMISSION = 'http://127.0.0.1/*'
const keepAlivePort = chrome.runtime.connect({ name: 'last-aperture-popup' })
const keepAliveTimer = setInterval(() => {
  keepAlivePort.postMessage({ type: 'KEEPALIVE' })
}, 20_000)
window.addEventListener('pagehide', () => {
  clearInterval(keepAliveTimer)
  keepAlivePort.disconnect()
}, { once: true })

const elements = {
  form: document.querySelector('#pairing-form'),
  port: document.querySelector('#controller-port'),
  pairingCode: document.querySelector('#pairing-code'),
  preview: document.querySelector('#preview'),
  binding: document.querySelector('#binding'),
  extensionId: document.querySelector('#extension-id'),
  targetOrigin: document.querySelector('#target-origin'),
  activeOrigin: document.querySelector('#active-origin'),
  campaignGrant: document.querySelector('#campaign-grant'),
  expiresAt: document.querySelector('#expires-at'),
  attach: document.querySelector('#attach'),
  close: document.querySelector('#close'),
  notice: document.querySelector('#notice'),
}

elements.extensionId.textContent = chrome.runtime.id

function setBusy(value) {
  elements.preview.disabled = value
  elements.attach.disabled = value
  elements.close.disabled = value
}

function setNotice(value) {
  elements.notice.textContent = value
}

function renderStatus(status) {
  const preview = status?.preview
  if (preview) {
    elements.binding.classList.remove('hidden')
    elements.targetOrigin.textContent = preview.target_origin
    elements.activeOrigin.textContent = status.active_tab_origin ?? 'Select the matching HTTPS tab'
    elements.campaignGrant.textContent = preview.campaign_grant_sha256
    elements.expiresAt.textContent = preview.expires_at
  }
  const attached = ['OPEN', 'PREPARED', 'COMMIT'].includes(status?.phase)
  elements.attach.classList.toggle('hidden', attached)
  elements.close.classList.toggle('hidden', !attached)
  if (status?.last_error) setNotice(status.last_error)
  else if (attached) setNotice(`Bridge ${status.phase.toLowerCase()}; controller requests use the active tab session.`)
}

async function companionMessage(message) {
  const response = await chrome.runtime.sendMessage(message)
  if (!response?.ok) throw new Error(response?.error ?? 'HTTP_AUTHED_BROWSER_COMPANION_FAILED')
  return response.value
}

async function ensureLoopbackPermission() {
  const permission = { origins: [LOOPBACK_PERMISSION] }
  if (await chrome.permissions.contains(permission)) return
  if (!await chrome.permissions.request(permission)) {
    throw new Error('HTTP_AUTHED_BROWSER_LOOPBACK_PERMISSION_REQUIRED')
  }
}

elements.form.addEventListener('submit', async (event) => {
  event.preventDefault()
  setBusy(true)
  setNotice('Reading the controller binding...')
  try {
    await ensureLoopbackPermission()
    const value = await companionMessage({
      type: 'LAST_APERTURE_PREVIEW',
      port: Number(elements.port.value),
      pairing_code: elements.pairingCode.value,
    })
    elements.pairingCode.value = ''
    renderStatus(value)
    setNotice('Verify the target and campaign, then attach the matching active tab.')
  } catch (error) {
    setNotice(error instanceof Error ? error.message : 'HTTP_AUTHED_BROWSER_COMPANION_FAILED')
  } finally {
    setBusy(false)
  }
})

elements.attach.addEventListener('click', async () => {
  setBusy(true)
  setNotice('Attaching the active tab...')
  try {
    const value = await companionMessage({ type: 'LAST_APERTURE_ATTACH' })
    renderStatus(value)
    setNotice('Attached. Keep this extension enabled until the campaign completes.')
  } catch (error) {
    setNotice(error instanceof Error ? error.message : 'HTTP_AUTHED_BROWSER_COMPANION_FAILED')
  } finally {
    setBusy(false)
  }
})

elements.close.addEventListener('click', async () => {
  setBusy(true)
  try {
    const value = await companionMessage({ type: 'LAST_APERTURE_CLOSE' })
    renderStatus(value)
    elements.binding.classList.add('hidden')
    setNotice('Bridge closed.')
  } catch (error) {
    setNotice(error instanceof Error ? error.message : 'HTTP_AUTHED_BROWSER_COMPANION_FAILED')
  } finally {
    setBusy(false)
  }
})

async function refreshStatus() {
  try {
    renderStatus(await companionMessage({ type: 'LAST_APERTURE_STATUS' }))
  } catch {
    // A transient service-worker restart is reflected on the next popup open.
  }
}

await refreshStatus()
