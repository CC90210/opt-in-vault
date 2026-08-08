import { createLogoutHandler } from "./handler";

describe("dashboard logout route", () => {
  it("expires the host-only session and returns to login", async () => {
    const response = await createLogoutHandler()(
      new Request("https://vault.example/api/auth/logout", {
        method: "POST",
        headers: { origin: "https://vault.example" },
      }),
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/login");
    expect(response.headers.get("set-cookie")).toContain(
      "__Host-opt_in_vault_session=;",
    );
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");
    expect(response.headers.get("set-cookie")).toContain("Secure");
  });

  it("rejects cross-origin logout attempts", async () => {
    const response = await createLogoutHandler()(
      new Request("https://vault.example/api/auth/logout", {
        method: "POST",
        headers: { origin: "https://attacker.example" },
      }),
    );

    expect(response.status).toBe(403);
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  it("rejects missing Origin and never reflects a request-controlled host", async () => {
    const handler = createLogoutHandler();
    const missingOrigin = await handler(
      new Request("https://vault.example/api/auth/logout", { method: "POST" }),
    );
    const poisonedHost = await handler(
      new Request("https://attacker-controlled.example/api/auth/logout", {
        method: "POST",
        headers: { origin: "https://attacker-controlled.example" },
      }),
    );

    expect(missingOrigin.status).toBe(403);
    expect(missingOrigin.headers.get("set-cookie")).toBeNull();
    expect(poisonedHost.headers.get("location")).toBe("/login");
  });
});
