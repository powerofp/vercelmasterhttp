export const runtime = "edge";
export const config = {
  runtime: "edge",
};

const AUTH_KEY = process.env.AUTH_KEY || "";

const SKIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
]);

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    const part = bytes.subarray(i, i + chunk);
    binary += String.fromCharCode(...part);
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function sanitizeHeaders(input) {
  const out = new Headers();
  if (!input || typeof input !== "object") {
    return out;
  }
  for (const [k, v] of Object.entries(input)) {
    const key = String(k).toLowerCase();
    if (SKIP_HEADERS.has(key)) {
      continue;
    }
    if (Array.isArray(v)) {
      for (const vv of v) out.append(k, String(vv));
    } else if (v !== undefined && v !== null) {
      out.set(k, String(v));
    }
  }
  return out;
}

function responseHeadersToObject(headers) {
  const out = {};
  for (const [k, v] of headers.entries()) {
    if (out[k] === undefined) {
      out[k] = v;
      continue;
    }
    if (Array.isArray(out[k])) {
      out[k].push(v);
    } else {
      out[k] = [out[k], v];
    }
  }
  return out;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function relaySingle(req) {
  if (!req.u || typeof req.u !== "string" || !/^https?:\/\//i.test(req.u)) {
    return { e: "bad url" };
  }

  const method = String(req.m || "GET").toUpperCase();
  const headers = sanitizeHeaders(req.h);
  const opts = {
    method,
    headers,
    redirect: req.r === false ? "manual" : "follow",
  };

  if (req.b) {
    opts.body = base64ToBytes(req.b);
    if (req.ct) {
      headers.set("content-type", String(req.ct));
    }
  }

  try {
    const resp = await fetch(req.u, opts);
    const buf = new Uint8Array(await resp.arrayBuffer());
    return {
      s: resp.status,
      h: responseHeadersToObject(resp.headers),
      b: bytesToBase64(buf),
    };
  } catch (err) {
    return { e: String(err) };
  }
}

function handleGet() {
  return new Response(
    "<!doctype html><html><body><h1>Relay OK</h1></body></html>",
    { status: 200, headers: { "content-type": "text/html; charset=utf-8" } },
  );
}

async function handlePost(request) {
  if (!AUTH_KEY) {
    return json({ e: "server auth key is not configured" }, 500);
  }

  let req;
  try {
    req = await request.json();
  } catch (err) {
    return json({ e: `bad json: ${String(err)}` }, 400);
  }

  if (req.k !== AUTH_KEY) {
    return json({ e: "unauthorized" }, 401);
  }

  if (Array.isArray(req.q)) {
    const results = await Promise.all(req.q.map((item) => relaySingle(item)));
    return json({ q: results });
  }

  return json(await relaySingle(req));
}

export function GET() {
  return handleGet();
}

export async function POST(request) {
  return handlePost(request);
}

export default async function handler(request) {
  const method = (request.method || "GET").toUpperCase();
  if (method === "POST") {
    return handlePost(request);
  }
  return handleGet();
}
