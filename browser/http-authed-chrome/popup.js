const byId = (id) => document.getElementById(id)

const elements = {
  attachPanel: byId('attach-panel'),
  attachForm: byId('attach-form'),
  port: byId('port'),
  capability: byId('capability'),
  review: byId('review'),
  previewOrigin: byId('preview-origin'),
  previewGrant: byId('preview-grant'),
  attach: byId('attach'),
  controlPanel: byId('control-panel'),
  origin: byId('origin'),
  campaignGrantDisplay: byId('campaign-grant-display'),
  phase: byId('phase'),
  completed: byId('completed'),
  preparedPanel: byId('prepared-panel'),
  preparedMethod: byId('prepared-method'),
  preparedUrl: byId('prepared-url'),
  preparedBinding: byId('prepared-binding'),
  detach: byId('detach'),
  notice: byId('notice'),
}

let busy = false
let reviewedBinding = null

function show(element, visible) {
  element.classList.toggle('hidden', !visible)
}

function notice(value) {
  elements.notice.textContent = value
}

function setBusy(value) {
  busy = value
  elements.review.disabled = value
  elements.attach.disabled = value || reviewedBinding === null
  elements.detach.disabled = value
}

function clearReviewedBinding() {
  reviewedBinding = null
  elements.previewOrigin.textContent = 'Load the controller binding.'
  elements.previewGrant.textContent = 'Load the controller binding.'
  elements.attach.disabled = true
}

function render(state) {
  const attached = state?.attached === true
  show(elements.attachPanel, !attached)
  show(elements.controlPanel, attached)
  if (!attached) {
    show(elements.preparedPanel, false)
    return
  }

  elements.origin.textContent = state.origin
  elements.campaignGrantDisplay.textContent = state.campaign_grant_sha256
  elements.phase.textContent = state.phase
  elements.completed.textContent = String(state.actions_completed)
  const prepared = state.prepared ?? null
  show(elements.preparedPanel, prepared !== null)
  if (prepared !== null) {
    elements.preparedMethod.textContent = prepared.method
    elements.preparedUrl.textContent = prepared.path_and_query
    elements.preparedBinding.textContent = `${prepared.action_binding_prefix}…`
  }

  if (state.failure_code !== null) {
    notice(`Campaign stopped safely (${state.failure_code}). No action will be retried.`)
  } else if (state.last_result !== null) {
    notice(`Last result: status ${state.last_result.status}, ${state.last_result.response_bytes} bytes.`)
  } else {
    notice('Campaign attached. Waiting for controller-authorized actions.')
  }
}

async function refresh(silent = false) {
  try {
    const reply = await chrome.runtime.sendMessage({ type: 'STATUS' })
    if (reply?.ok === true) render(reply.state)
    else if (!silent) notice(`Bridge status unavailable (${reply?.error_code ?? 'BRIDGE_UNAVAILABLE'}).`)
  } catch {
    if (!silent) notice('The in-memory bridge is unavailable. Reattach the authorized tab.')
    render({ attached: false })
  }
}

for (const field of [elements.port, elements.capability]) {
  field.addEventListener('input', clearReviewedBinding)
}

elements.review.addEventListener('click', async () => {
  if (busy || !elements.port.reportValidity() || !elements.capability.reportValidity()) return
  setBusy(true)
  try {
    const reply = await chrome.runtime.sendMessage({
      type: 'PREVIEW_CONTROLLER',
      port: Number(elements.port.value),
      capability: elements.capability.value,
    })
    if (reply?.ok !== true) throw new Error('preview refused')
    reviewedBinding = {
      origin: reply.origin,
      campaign_grant_sha256: reply.campaign_grant_sha256,
    }
    elements.previewOrigin.textContent = reviewedBinding.origin
    elements.previewGrant.textContent = reviewedBinding.campaign_grant_sha256
    notice('Verify this exact origin and grant, then attach to start the campaign.')
  } catch {
    clearReviewedBinding()
    notice('The controller binding could not be verified for this extension and tab.')
  } finally {
    setBusy(false)
  }
})

elements.attachForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  if (busy || reviewedBinding === null || !elements.attachForm.reportValidity()) return
  const pending = chrome.runtime.sendMessage({
    type: 'ATTACH',
    port: Number(elements.port.value),
    capability: elements.capability.value,
    campaign_grant_sha256: reviewedBinding.campaign_grant_sha256,
    reviewed_origin: reviewedBinding.origin,
  })
  elements.capability.value = ''
  setBusy(true)
  try {
    const reply = await pending
    if (reply?.ok === true) {
      reviewedBinding = null
      render(reply.state)
      notice('Campaign attached. Automatic controller-authorized execution has started.')
    } else {
      render(reply?.state ?? { attached: false })
      notice(`Attach refused (${reply?.error_code ?? 'BRIDGE_UNAVAILABLE'}).`)
      clearReviewedBinding()
    }
  } catch {
    render({ attached: false })
    notice('The loopback controller could not be reached.')
    clearReviewedBinding()
  } finally {
    setBusy(false)
  }
})

elements.detach.addEventListener('click', async () => {
  if (busy) return
  setBusy(true)
  try {
    const reply = await chrome.runtime.sendMessage({ type: 'DETACH' })
    render(reply?.state ?? { attached: false })
    clearReviewedBinding()
    notice('Emergency stop requested. The in-memory campaign capability was discarded.')
  } catch {
    render({ attached: false })
    clearReviewedBinding()
    notice('The bridge worker is gone; its memory-only capability is no longer available.')
  } finally {
    setBusy(false)
  }
})

await refresh(true)
globalThis.setInterval(() => { void refresh(true) }, 500)
