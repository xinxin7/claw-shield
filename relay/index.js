const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "te",
  "trailer",
  // Let fetch set Host for target origin.
  "host",
]);

function buildTargetUrl(requestUrl, targetBase) {
  const incoming = new URL(requestUrl);
  const base = new URL(targetBase);
  return new URL(`${incoming.pathname}${incoming.search}`, base).toString();
}

function forwardHeaders(incomingHeaders) {
  const headers = new Headers();
  for (const [name, value] of incomingHeaders.entries()) {
    if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) {
      continue;
    }
    headers.append(name, value);
  }
  return headers;
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const targetBase = env.TARGET;
    if (!targetBase) {
      return new Response("TARGET is not configured", { status: 500 });
    }

    const targetUrl = buildTargetUrl(request.url, targetBase);
    const targetHost = new URL(targetUrl).host;
    const headers = forwardHeaders(request.headers);
    const relaySharedToken = env.RELAY_SHARED_TOKEN;
    if (!relaySharedToken) {
      return new Response("RELAY_SHARED_TOKEN is not configured", { status: 500 });
    }

    headers.set("accept", "message/ohttp-res");
    headers.set("host", targetHost);
    headers.set("x-claw-shield-relay-token", relaySharedToken);

    const upstreamResponse = await fetch(targetUrl, {
      method: "POST",
      headers,
      body: request.body,
    });

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: upstreamResponse.headers,
    });
  },
};
