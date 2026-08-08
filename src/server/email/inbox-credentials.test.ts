import {
  createInboxCredentialBinding,
  parseInboxCredentialPayload,
} from "./inbox-credentials";

const TEST_DKIM_PRIVATE_KEY = [
  "-----BEGIN " + "PRIVATE KEY-----",
  "test fixture only",
  "-----END " + "PRIVATE KEY-----",
].join("\n");

describe("inbox credential payloads", () => {
  it("binds one encrypted payload to both canonical mail endpoints", () => {
    expect(
      createInboxCredentialBinding({
        smtpHost: "SMTP.Example.COM.",
        imapHost: "imap.example.com",
      }),
    ).toBe("oiv-inbox-v1|smtp=smtp.example.com|imap=imap.example.com");
    expect(() =>
      createInboxCredentialBinding({
        smtpHost: "smtp.example.com/path",
        imapHost: "imap.example.com",
      }),
    ).toThrow(/host/i);
  });

  it("accepts bounded SMTP/OAuth/IMAP material and rejects unknown fields", () => {
    expect(
      parseInboxCredentialPayload(
        JSON.stringify({
          username: "sender@example.com",
          accessToken: "imap-access-token",
          oauth2: {
            clientId: "client-id",
            clientSecret: "client-secret",
            refreshToken: "refresh-token",
          },
          dkimPrivateKey: TEST_DKIM_PRIVATE_KEY,
        }),
      ),
    ).toMatchObject({
      username: "sender@example.com",
      accessToken: "imap-access-token",
      oauth2: { refreshToken: "refresh-token" },
    });
    expect(() =>
      parseInboxCredentialPayload(
        JSON.stringify({ username: "a@example.com", password: "x", extra: true }),
      ),
    ).toThrow(/credentials/i);
  });
});
