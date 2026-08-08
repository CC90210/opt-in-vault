(function (global) {
  "use strict";

  var SITE_KEY = /^oiv_pk_[A-Za-z0-9_-]{43}$/;
  var ACTION = /^[a-z][a-z0-9_-]{1,63}$/;

  function requiredString(name, value, maximum) {
    if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
      throw new TypeError(name + " is required and must be at most " + maximum + " characters.");
    }
    return value;
  }

  function idempotencyKey(input) {
    if (input !== undefined) return requiredString("idempotencyKey", input, 128);
    if (!crypto || typeof crypto.randomUUID !== "function") {
      throw new Error("A browser with crypto.randomUUID or an explicit idempotencyKey is required.");
    }
    return crypto.randomUUID();
  }

  async function capture(input) {
    if (!input || typeof input !== "object") throw new TypeError("Capture options are required.");
    var siteKey = requiredString("siteKey", input.siteKey, 64);
    if (!SITE_KEY.test(siteKey)) throw new TypeError("siteKey is not a publishable Opt-in Vault key.");
    var action = requiredString("affirmativeAction", input.affirmativeAction, 64);
    if (!ACTION.test(action)) throw new TypeError("affirmativeAction is invalid.");
    if (!input.email && !input.phone) throw new TypeError("An email or phone value is required.");

    var endpoint = new URL(
      input.endpoint || "/api/v1/consent/log",
      location.href,
    ).toString();
    var payload = {
      disclosure_version: requiredString("disclosureVersion", input.disclosureVersion, 128),
      affirmative_action: action,
      form_url: input.formUrl || location.href,
      occurred_at: input.occurredAt || new Date().toISOString(),
    };
    if (input.email) payload.email = requiredString("email", input.email, 254);
    if (input.phone) payload.phone = requiredString("phone", input.phone, 32);

    var response = await fetch(endpoint, {
      method: "POST",
      mode: "cors",
      credentials: "omit",
      redirect: "error",
      headers: {
        "Content-Type": "application/json",
        "X-OptInVault-Site-Key": siteKey,
        "Idempotency-Key": idempotencyKey(input.idempotencyKey),
      },
      body: JSON.stringify(payload),
    });
    var result;
    try {
      result = await response.json();
    } catch {
      result = null;
    }
    if (!response.ok) {
      var code = result && typeof result.error === "string" ? result.error : "request_failed";
      var failure = new Error("Opt-in Vault capture failed (" + response.status + "): " + code);
      failure.code = code;
      failure.status = response.status;
      throw failure;
    }
    return result;
  }

  global.OptInVault = Object.freeze({ capture: capture, version: "1.0.0" });
})(window);
