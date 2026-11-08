import { isScanReport } from "@/lib/report";

export const runtime = "nodejs";
export const maxDuration = 60;

function json(data: unknown, status: number, extraHeaders?: HeadersInit) {
  const headers = new Headers(extraHeaders);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return Response.json(data, { status, headers });
}

async function readLimited(stream: ReadableStream<Uint8Array> | null, limit: number) {
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new RangeError("Body too large");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks).toString("utf8");
}

export async function POST(request: Request) {
  // A browser must submit through this app's origin. Tokens stay on the server.
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) return json({ error: "Cross-origin scan requests are not allowed." }, 403);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return json({ error: "Content-Type must be application/json." }, 415);
  }
  let body: unknown;
  try {
    body = JSON.parse(await readLimited(request.body, 8192));
  } catch (error) {
    return json({ error: error instanceof RangeError ? "Request body is too large." : "Invalid JSON request." }, error instanceof RangeError ? 413 : 400);
  }
  let endpoint: URL;
  try {
    endpoint = new URL("/scan", process.env.SCANNER_API_URL || "http://127.0.0.1:5000");
    if (!["http:", "https:"].includes(endpoint.protocol) || endpoint.username || endpoint.password) throw new Error();
  } catch { return json({ error: "The scanner service is not configured correctly." }, 503); }
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (process.env.SCANNER_API_KEY) headers.Authorization = `Bearer ${process.env.SCANNER_API_KEY}`;
    const response = await fetch(endpoint, {
      method: "POST", headers, body: JSON.stringify(body), cache: "no-store",
      redirect: "error", signal: AbortSignal.timeout(55_000),
    });
    const data: unknown = JSON.parse(await readLimited(response.body, 2_097_152));
    const retryAfter = response.headers.get("Retry-After");
    const retry = retryAfter && /^\d{1,4}$/.test(retryAfter) ? { "Retry-After": retryAfter } : undefined;
    if (isScanReport(data) && (response.ok || response.status === 422)) return json(data, response.status, retry);
    if (!response.ok && typeof data === "object" && data !== null && "error" in data && typeof data.error === "string") {
      if (response.status === 401 || response.status >= 500 && response.status !== 503) {
        return json({ error: "The scanner service is unavailable. Check the server configuration." }, 502);
      }
      return json({ error: data.error }, response.status, retry);
    }
    return json({ error: "The scanner returned an invalid report." }, 502);
  } catch (error) {
    const timeout = error instanceof Error && error.name === "TimeoutError";
    return json({ error: timeout ? "The scanner timed out. Try a smaller page limit." : "Unable to reach the scanner service. Please try again later." }, timeout ? 504 : 502);
  }
}
