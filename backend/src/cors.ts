const corsBaseHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*",
};

export function withCorsHeaders(init: HeadersInit = {}) {
  const headers = new Headers(init);
  for (const [key, value] of Object.entries(corsBaseHeaders)) {
    headers.set(key, value);
  }
  return headers;
}

export function createCorsPreflightResponse(request: Request) {
  const requestedHeaders = request.headers.get("access-control-request-headers");
  const headers = withCorsHeaders({
    ...(requestedHeaders ? { "Access-Control-Allow-Headers": requestedHeaders } : {}),
    "Access-Control-Max-Age": "86400",
  });

  return new Response(null, { status: 204, headers });
}
