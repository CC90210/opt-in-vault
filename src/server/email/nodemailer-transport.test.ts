import { buildNodemailerTransportOptions } from "./nodemailer-transport";

describe("Nodemailer transport configuration", () => {
  it("binds local DKIM signing to both RFC 8058 headers", () => {
    const result = buildNodemailerTransportOptions({
      provider: "smtp",
      host: "smtp.example.com",
      port: 465,
      secure: true,
      username: "sender@example.com",
      password: "secret",
      dkim: {
        domainName: "example.com",
        keySelector: "outbound",
        privateKey: "test-private-key",
      },
    });

    expect(result.dkim).toEqual(
      expect.objectContaining({
        headerFieldNames: expect.stringContaining("list-unsubscribe"),
      }),
    );
    expect(result.dkim?.headerFieldNames).toContain("list-unsubscribe-post");
  });

  it("does not pretend provider-managed DKIM is locally configured", () => {
    const result = buildNodemailerTransportOptions({
      provider: "google",
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      username: "sender@example.com",
      oauth2: {
        accessToken: "current-access-token",
      },
    });

    expect(result.dkim).toBeUndefined();
    expect(result.auth).toEqual(expect.objectContaining({ type: "OAuth2" }));
  });

  it("requires OAuth refresh to finish before the SMTP transport is built", () => {
    expect(() =>
      buildNodemailerTransportOptions({
        provider: "google",
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        username: "sender@example.com",
        oauth2: {
          clientId: "client",
          clientSecret: "secret",
          refreshToken: "refresh",
        },
      }),
    ).toThrow(/access token/i);
  });

  it("rejects TLS downgrades and invalid SMTP port/secure combinations", () => {
    const base = {
      provider: "smtp" as const,
      host: "smtp.example.com",
      username: "sender@example.com",
      password: "secret",
    };
    expect(() =>
      buildNodemailerTransportOptions({
        ...base,
        port: 465,
        secure: false,
      }),
    ).toThrow(/TLS/i);
    expect(() =>
      buildNodemailerTransportOptions({
        ...base,
        port: 587,
        secure: true,
      }),
    ).toThrow(/TLS/i);
  });
});
