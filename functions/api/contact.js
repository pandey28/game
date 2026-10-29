export async function onRequestPost({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  const reply = (message, status) =>
    new Response(JSON.stringify({ success: status === 200, message }), {
      status,
      headers,
    });

  try {
    const form = await request.formData();

    const name = String(form.get("name") || "").trim();
    const email = String(form.get("email") || "").trim();
    const message = String(form.get("message") || "").trim();
    const token = String(
      form.get("cf-turnstile-response") || ""
    ).trim();

    if (!name || !email || !message || !token) {
      return reply("Complete all fields and CAPTCHA.", 400);
    }

    if (
      name.length > 100 ||
      email.length > 254 ||
      message.length > 5000 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return reply("Please check your details.", 400);
    }

    if (!env.TURNSTILE_SECRET) {
      return reply("Contact form is not configured.", 500);
    }

    const verifyResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET,
          response: token,
        }),
      }
    );

    if (!verifyResponse.ok) {
      console.error("Turnstile service returned HTTP", verifyResponse.status);
      return reply("CAPTCHA verification is temporarily unavailable.", 502);
    }

    const verification = await verifyResponse.json();

    if (
      !verification.success ||
      ![
        "ashishpandey.com.np",
        "www.ashishpandey.com.np",
      ].includes(verification.hostname)
    ) {
      return reply("CAPTCHA verification failed. Try again.", 403);
    }

    const emailResponse = await fetch(
      "https://formsubmit.co/ajax/pandeyashish2056@gmail.com",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          name,
          email,
          message,
          _subject: "New portfolio contact message",
        }),
      }
    );

    const result = await emailResponse.json().catch(() => null);

    if (!emailResponse.ok || result?.success !== "true") {
      console.error("FormSubmit rejected the request:", {
        httpStatus: emailResponse.status,
        providerMessage:
          typeof result?.message === "string"
            ? result.message
            : "No provider message returned",
      });

      return reply(
        "Could not send your message. Please try again later.",
        502
      );
    }

    return reply("Your message was sent successfully!", 200);
  } catch (error) {
    console.error(
      "Contact form request failed:",
      error instanceof Error ? error.message : "Unknown error"
    );

    return reply("Something went wrong. Try again later.", 500);
  }
}
