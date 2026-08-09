import { describe, expect, it, vi } from "vitest";

import { CaptureSiteValidationError } from "@/server/consent/sites";

import { createSiteCreateHandler } from "./handler";

describe("POST /api/v1/sites handler", () => {
  it("returns 401 unauthorized when principal is missing", async () => {
    const handler = createSiteCreateHandler({
      authorize: async () => null,
      createSite: async () => {
        throw new Error("Should not be called");
      },
    });

    const res = await handler(
      new Request("https://vault.example/api/v1/sites", {
        method: "POST",
        body: JSON.stringify({ name: "Site" }),
      }),
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body).toEqual({ error: "unauthorized" });
  });

  it("returns 400 invalid_request on malformed JSON body", async () => {
    const handler = createSiteCreateHandler({
      authorize: async () => ({ tenantId: "tenant-1" }),
      createSite: async () => {
        throw new Error("Should not be called");
      },
    });

    const res = await handler(
      new Request("https://vault.example/api/v1/sites", {
        method: "POST",
        body: "invalid-json",
      }),
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body).toEqual({ error: "invalid_request" });
  });

  it("returns 400 with detail when CaptureSiteValidationError is thrown", async () => {
    const handler = createSiteCreateHandler({
      authorize: async () => ({ tenantId: "tenant-1" }),
      createSite: async () => {
        throw new CaptureSiteValidationError("Allowed origins must not repeat.");
      },
    });

    const res = await handler(
      new Request("https://vault.example/api/v1/sites", {
        method: "POST",
        body: JSON.stringify({ name: "Site" }),
      }),
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body).toEqual({
      error: "invalid_request",
      detail: "Allowed origins must not repeat.",
    });
  });

  it("returns 201 created on successful site creation", async () => {
    const mockSite = {
      id: "site-123",
      name: "Main Site",
      publicKeyPrefix: "oiv_pk_1234567890",
      allowedOrigins: ["https://example.com"],
      formUrlPattern: null,
      disclosureVersion: "1.0",
      controller: "Corp",
      purpose: "Signups",
      channels: ["email"],
      status: "active" as const,
      createdAt: 1700000000000,
    };

    const handler = createSiteCreateHandler({
      authorize: async () => ({ tenantId: "tenant-1" }),
      createSite: async () => ({
        site: mockSite,
        site_key: "oiv_pk_rawkey1234567890",
        snippet: "<script>...</script>",
      }),
    });

    const res = await handler(
      new Request("https://vault.example/api/v1/sites", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Main Site" }),
      }),
    );

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.site.id).toBe("site-123");
    expect(body.site_key).toBe("oiv_pk_rawkey1234567890");
    expect(body.snippet).toBe("<script>...</script>");
  });
});
