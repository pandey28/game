// functions/api/contact.js  ->  handles POST /api/contact on Cloudflare Pages
//
// Flow: read JSON -> check honeypot -> validate fields -> verify Turnstile (server side)
//       -> forward to FormSubmit -> report success ONLY if FormSubmit says it succeeded.
//
// Secrets: the Turnstile SECRET key is read from the Pages secret `TURNSTILE_SECRET`.
// It is never sent to the browser and never logged.

const TO_EMAIL = "pandeyashish2056@gmail.com";
const SITE_ORIGIN = "https://www.ashishpandey.com.np";
const ALLOWED_HOSTNAMES = ["ashishpandey.com.np", "www.ashishpandey.com.np"];
const TURNSTILE_VERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const LIMITS = { name: 100, email: 254, message: 5000, token: 2048, body: 20000 };
const PROVIDER_TIMEOUT_MS = 10000;

// ---------- small helpers ----------

const respond = (ref, status, code, message, extraHeaders = {}) =>
  new Response(
    JSON.stringify({ success: status === 200, code, message, ref }),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        ...extraHeaders,
      },
    },
  );

// Safe diagnostic log: only short codes and numbers. NEVER pass the visitor's
// name, email, message, the CAPTCHA token or any secret in here.
const log = (ref, stage, details = {}) =>
  console.log(JSON.stringify({ app: "contact-form", ref, stage, ...details }));

const text = (value) => (typeof value === "string" ? value.trim() : "");

const shorten = (value) =>
  typeof value === "string" ? value.replace(/\s+/g, " ").slice(0, 160) : "";

// Accepts JSON (what the website sends) and also normal form posts.
async function readBody(request) {
  const type = (request.headers.get("content-type") || "").toLowerCase();

  if (type.includes("application/json")) {
    const data = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("invalid_body");
    }
    return data;
  }

  if (type.includes("form")) {
    const form = await request.formData();
    return {
      name: form.get("name"),
      email: form.get("email"),
      message: form.get("message"),
      website: form.get("website") ?? form.get("_honey"),
      turnstileToken:
        form.get("turnstileToken") ?? form.get("cf-turnstile-response"),
    };
  }

  throw new Error("unsupported_content_type");
}

// ---------- the route ----------

export async function onRequestPost({ request, env }) {
  const ref = crypto.randomUUID().slice(0, 8); // lets you match a browser error to a log line
  const started = Date.now();
  // same as log(), but also records total milliseconds so far (to find slow steps)
  const note = (stage, details = {}) =>
    log(ref, stage, { ...details, totalMs: Date.now() - started });

  try {
    // 1) Read and parse the request
    const length = Number(request.headers.get("content-length") || 0);
    if (length > LIMITS.body) {
      note("rejected_too_large");
      return respond(ref, 413, "too_large", "Your message is too large.");
    }

    let data;
    try {
      data = await readBody(request);
    } catch {
      note("rejected_bad_request");
      return respond(ref, 400, "bad_request", "The request could not be read.");
    }

    const name = text(data.name);
    const email = text(data.email);
    const message = text(data.message);
    const token = text(data.turnstileToken);
    const honey = text(data.website) || text(data._honey);

    // 2) Honeypot: real visitors leave it empty. Pretend success, send nothing.
    if (honey) {
      note("honeypot_triggered");
      return respond(ref, 200, "ok", "Thank you! Your message has been received.");
    }

    // 3) Validate input
    if (!token) {
      note("rejected_missing_token");
      return respond(
        ref,
        400,
        "missing_token",
        "Please complete the security check and try again.",
      );
    }
    if (
      !name ||
      !email ||
      !message ||
      name.length > LIMITS.name ||
      email.length > LIMITS.email ||
      message.length > LIMITS.message ||
      token.length > LIMITS.token ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      note("rejected_invalid_fields", {
        hasName: Boolean(name),
        hasEmail: Boolean(email),
        hasMessage: Boolean(message),
      });
      return respond(
        ref,
        400,
        "invalid_fields",
        "Please check your name, email and message and try again.",
      );
    }

    if (!env.TURNSTILE_SECRET) {
      note("config_missing_turnstile_secret");
      return respond(ref, 500, "not_configured", "The contact form is not configured yet.");
    }

    // 4) Verify the Turnstile token with Cloudflare (server side)
    let verification;
    const turnstileStart = Date.now();
    try {
      const params = new URLSearchParams({
        secret: env.TURNSTILE_SECRET,
        response: token,
      });
      const ip = request.headers.get("CF-Connecting-IP");
      if (ip) params.set("remoteip", ip);

      const verifyResponse = await fetch(TURNSTILE_VERIFY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params,
        signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      });

      if (!verifyResponse.ok) {
        note("turnstile_http_error", { httpStatus: verifyResponse.status });
        return respond(
          ref,
          502,
          "captcha_unavailable",
          "The security check is temporarily unavailable. Please try again.",
        );
      }
      verification = await verifyResponse.json();
      note("turnstile_checked", { turnstileMs: Date.now() - turnstileStart });
    } catch (error) {
      note("turnstile_unreachable", {
        error: error instanceof Error ? error.name : "unknown",
      });
      return respond(
        ref,
        502,
        "captcha_unavailable",
        "The security check is temporarily unavailable. Please try again.",
      );
    }

    if (!verification || verification.success !== true) {
      const codes = Array.isArray(verification?.["error-codes"])
        ? verification["error-codes"].map(String).slice(0, 5)
        : [];
      note("turnstile_failed", { codes });

      if (
        codes.includes("invalid-input-secret") ||
        codes.includes("missing-input-secret")
      ) {
        return respond(ref, 500, "not_configured", "The contact form is not configured correctly.");
      }
      if (codes.includes("timeout-or-duplicate")) {
        return respond(
          ref,
          403,
          "captcha_expired",
          "The security check expired. Please tick it again and resend.",
        );
      }
      return respond(ref, 403, "captcha_failed", "Security check failed. Please try again.");
    }

    if (!ALLOWED_HOSTNAMES.includes(verification.hostname)) {
      note("turnstile_wrong_hostname", {
        hostname: shorten(String(verification.hostname || "")),
      });
      return respond(ref, 403, "captcha_hostname", "Security check failed. Please try again.");
    }

    // 5) Forward to FormSubmit and check the response BODY, not just the HTTP status
    let providerResponse;
    let providerText;
    const mailStart = Date.now();
    try {
      providerResponse = await fetch(`https://formsubmit.co/ajax/${TO_EMAIL}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          // FormSubmit's AJAX endpoint is built for browsers; tell it which site this is.
          Origin: SITE_ORIGIN,
          Referer: `${SITE_ORIGIN}/`,
        },
        body: JSON.stringify({
          name,
          email,
          message,
          _subject: "New portfolio contact message",
          _template: "table",
          _captcha: "false", // Turnstile already did the bot check
        }),
        signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      });
      providerText = await providerResponse.text();
      note("mail_provider_answered", { mailMs: Date.now() - mailStart });
    } catch (error) {
      note("mail_provider_unreachable", {
        error: error instanceof Error ? error.name : "unknown",
      });
      return respond(
        ref,
        502,
        "mail_unavailable",
        "Could not send your message right now. Please try again later.",
      );
    }

    let result = null;
    try {
      result = JSON.parse(providerText);
    } catch {
      result = null;
    }

    // FormSubmit answers {"success":"true", ...} (a string). Accept true too.
    const sent =
      providerResponse.ok &&
      result !== null &&
      (result.success === true || result.success === "true");

    if (!sent) {
      note("mail_provider_rejected", {
        httpStatus: providerResponse.status,
        providerSuccess: result ? String(result.success) : "not-json",
        providerMessage: shorten(result?.message),
        contentType: shorten(providerResponse.headers.get("content-type") || ""),
      });
      return respond(
        ref,
        502,
        "mail_failed",
        "Could not send your message right now. Please try again later.",
      );
    }

    note("sent");
    return respond(ref, 200, "sent", "Your message was sent successfully!");
  } catch (error) {
    note("unexpected_error", {
      error: error instanceof Error ? error.name : "unknown",
    });
    return respond(ref, 500, "server_error", "Something went wrong. Please try again later.");
  }
}

// Any other method (GET, PUT, ...) gets a clean JSON answer instead of the web page.
export function onRequest() {
  return respond("-", 405, "method_not_allowed", "Please use POST.", { Allow: "POST" });
}
