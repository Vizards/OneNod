(() => {
  // This closure lives in the extension's isolated world for this document.
  if (globalThis.oneNodFieldsInstalled) return;
  globalThis.oneNodFieldsInstalled = true;
  let pending;

  function find(selector) {
    const matches = [];
    function visit(root) {
      matches.push(...root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) if (el.shadowRoot) visit(el.shadowRoot);
    }
    visit(document);
    return matches.length === 1 ? matches[0] : null;
  }

  function canFill(el) {
    if (!el || !el.isConnected || el.matches(":disabled") || el.readOnly) return false;
    return el instanceof HTMLTextAreaElement || el.isContentEditable ||
      (el instanceof HTMLInputElement &&
       ["text","password","email","search","url","tel","number"].includes(el.type));
  }

  function write(el, value) {
    if (el.isContentEditable) el.textContent = value;
    else {
      const prototype = el instanceof HTMLInputElement ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
      Object.getOwnPropertyDescriptor(prototype, "value").set.call(el, value);
    }
    el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  chrome.runtime.onMessage.addListener((request, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return;
    try {
      if (request.op === "prepare") {
        pending = null;
        if (location.href !== request.frame) return respond({status:"target_changed"});
        const fields = request.fields.map(find);
        if (!fields.every(canFill) || new Set(fields).size !== fields.length)
          return respond({status:"field_missing_or_ambiguous"});
        const submit = request.submit ? find(request.submit) : null;
        if (request.submit && !(submit instanceof HTMLElement))
          return respond({status:"submit_missing_or_ambiguous"});
        pending = { id:request.id, url:location.href, fields, selectors:request.fields,
          submit, submitSelector:request.submit };
        return respond({status:"ready"});
      }
      if (request.op !== "apply") return;
      const job = pending;
      pending = null;
      if (!job || job.id !== request.id || job.url !== location.href ||
          job.fields.length !== request.values.length ||
          !job.fields.every((el,i) => canFill(el) && el === find(job.selectors[i])) ||
          (job.submit && job.submit !== find(job.submitSelector)))
        return respond({status:"target_changed"});
      for (const [i, el] of job.fields.entries()) {
        if (location.href !== job.url || !canFill(el) || el !== find(job.selectors[i]))
          return respond({status:"target_changed_during_fill"});
        write(el, request.values[i]);
      }
      if (!job.submit) return respond({status:"filled"});
      // Let framework updates settle, then use the site's ordinary submit control.
      setTimeout(() => {
        if (location.href !== job.url || !job.submit.isConnected ||
            job.submit !== find(job.submitSelector) || job.submit.matches(":disabled"))
          return respond({status:"filled_submit_unavailable"});
        respond({status:"submit_dispatched"});
        job.submit.click();
      }, 0);
      return true;
    } catch {
      respond({status:"field_operation_failed"});
    }
  });
})();
