import test from "node:test";
import assert from "node:assert/strict";
import { sameOriginRequest } from "../lib/request.ts";

test("accepts the browser Host when Next internally uses localhost", () => {
  assert.equal(sameOriginRequest("http://localhost:3000/api/scan", "127.0.0.1:3000", "http://127.0.0.1:3000"), true);
});

test("rejects cross-origin and malformed browser requests", () => {
  for (const origin of ["https://evil.example", "http://localhost:3001", "https://localhost:3000", "null", "http://user@localhost:3000", "http://localhost:3000/path"]) {
    assert.equal(sameOriginRequest("http://localhost:3000/api/scan", "localhost:3000", origin), false);
  }
});

test("supports an explicit trusted public origin behind a proxy", () => {
  assert.equal(sameOriginRequest("http://localhost:3000/api/scan", "localhost:3000", "https://scanner.example.com", "https://scanner.example.com"), true);
  assert.equal(sameOriginRequest("http://localhost:3000/api/scan", "evil.example", "https://evil.example", "https://scanner.example.com"), false);
  assert.equal(sameOriginRequest("http://localhost:3000/api/scan", null, null), true);
});
