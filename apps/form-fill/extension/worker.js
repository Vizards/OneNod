const hostName = "cc.onenod.form_fill";
let nativePort;
let prepared;

function connect() {
  if (nativePort) return;
  const port = chrome.runtime.connectNative(hostName);
  nativePort = port;
  port.onMessage.addListener(async (message) => {
    let reply;
    try {
      reply = await handle(message);
    } catch {
      reply = { status: "browser_operation_failed" };
    }
    if (nativePort === port) port.postMessage(reply);
  });
  port.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    if (nativePort === port) {
      nativePort = undefined;
      prepared = undefined;
    }
  });
}

function start() {
  chrome.alarms.create("reconnect", { periodInMinutes: 1 });
  connect();
}
chrome.runtime.onInstalled.addListener(start);
chrome.runtime.onStartup.addListener(start);
chrome.action.onClicked.addListener(connect);
chrome.alarms.onAlarm.addListener(connect);
connect();

async function locate(request) {
  const target = new URL(request.url).href;
  const tabs = (await chrome.tabs.query({})).filter(tab =>
    tab.url === target && (request.tab == null || tab.id === request.tab));
  if (!tabs.length) return { status: "no_tab" };
  return { status: "matches", tabs: tabs.map(tab => tab.id) };
}

async function handle(request) {
  if (request.op === "locate") return locate(request);
  if (request.op === "cancel") {
    prepared = undefined;
    return { status: "cancelled" };
  }
  if (request.op === "prepare") {
    prepared = undefined;
    const tab = await chrome.tabs.get(request.tab);
    const page = new URL(request.url).href;
    if (tab.url !== page) return { status: "target_changed" };
    const frame = request.frame ? new URL(request.frame).href : page;
    let target = { tabId: tab.id, frameIds: [0] };
    if (request.frame) {
      const frames = await chrome.scripting.executeScript({
        target: { tabId: tab.id, allFrames: true },
        func: () => location.href
      });
      const matches = frames.filter(result => result.result === frame);
      if (matches.length !== 1) return { status: "frame_missing_or_ambiguous" };
      target = { tabId: tab.id, documentIds: [matches[0].documentId] };
    }
    const [injection] = await chrome.scripting.executeScript({ target, files: ["fields.js"] });
    const opts = { documentId: injection.documentId };
    const result = await chrome.tabs.sendMessage(tab.id, {
      op: "prepare", id: request.id, frame, fields: request.fields, submit: request.submit
    }, opts);
    if (result?.status === "ready") prepared = { id: request.id, tab: tab.id, page, opts };
    return result;
  }
  if (request.op === "apply") {
    const job = prepared;
    prepared = undefined;
    if (!job || job.id !== request.id || (await chrome.tabs.get(job.tab)).url !== job.page)
      return { status: "target_changed" };
    return await chrome.tabs.sendMessage(job.tab, request, job.opts);
  }
  if (request.op === "verify") {
    const tab = await chrome.tabs.get(request.tab);
    if (tab.url !== new URL(request.url).href) return { status: "not_matched" };
    if (request.text) {
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [0] },
        func: (url, text) => location.href === url && document.body.innerText.includes(text),
        args: [tab.url, request.text]
      });
      if (!result.result) return { status: "not_matched" };
    }
    return { status: "verified" };
  }
  return { status: "bad_request" };
}
