export function sameOriginRequest(requestUrl: string, host: string | null, origin: string | null, configuredOrigin?: string) {
  if (!origin) return true; // API clients are not authenticated through Origin.
  try {
    const incoming = new URL(origin);
    const request = new URL(requestUrl);
    // Next's internal request URL can use localhost even when the browser uses
    // another Host. Reverse proxies can set an explicit public origin instead.
    const expected = new URL(configuredOrigin || `${request.protocol}//${host || request.host}`);
    return ["http:", "https:"].includes(incoming.protocol) &&
      !incoming.username && !incoming.password && origin === incoming.origin &&
      incoming.origin === expected.origin;
  } catch { return false; }
}
