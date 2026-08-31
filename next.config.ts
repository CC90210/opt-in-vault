import type { NextConfig } from "next";

function contentSecurityPolicy(isProduction: boolean): string {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `script-src 'self' 'unsafe-inline'${isProduction ? "" : " 'unsafe-eval'"}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    `connect-src 'self'${isProduction ? "" : " ws: wss:"}`,
  ].join("; ");
}

function securityHeaders(): Array<{ key: string; value: string }> {
  const isProduction = process.env.NODE_ENV === "production";
  const headers = [
    { key: "Content-Security-Policy", value: contentSecurityPolicy(isProduction) },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "no-referrer" },
    {
      key: "Permissions-Policy",
      value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    },
  ];
  if (isProduction) {
    headers.push({
      key: "Strict-Transport-Security",
      value: "max-age=31536000",
    });
  }
  return headers;
}

const nextConfig: NextConfig = {
  // Next's output tracing drops @libsql/isomorphic-ws, the WebSocket shim
  // hrana-client imports, which breaks the OpenNext/Cloudflare bundle step.
  // Its workerd export is a dependency-free wrapper, so force-including it is
  // safe on every target. Same fix as breeze-portal and ig-setter-pro.
  outputFileTracingIncludes: {
    "/**/*": ["./node_modules/@libsql/isomorphic-ws/**/*"],
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders() }];
  },
};

export default nextConfig;
