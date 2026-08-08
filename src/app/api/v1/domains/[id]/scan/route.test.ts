import { createDomainScanHandler } from "./handler";

describe("tenant-scoped domain scan route", () => {
  it("derives tenant identity from auth rather than request data", async () => {
    const scan = vi.fn().mockResolvedValue({ status: "healthy" });
    const handler = createDomainScanHandler({
      authorize: vi.fn().mockResolvedValue({ tenantId: "tenant-from-auth" }),
      scan,
    });
    const response = await handler(
      new Request("https://vault.example/api/v1/domains/forged/scan", { method: "POST" }),
      { params: Promise.resolve({ id: "domain-1" }) },
    );
    expect(response.status).toBe(200);
    expect(scan).toHaveBeenCalledWith({
      tenantId: "tenant-from-auth",
      domainId: "domain-1",
    });
  });

  it("does no DNS or database work when authorization fails", async () => {
    const scan = vi.fn();
    const handler = createDomainScanHandler({
      authorize: vi.fn().mockResolvedValue(null),
      scan,
    });
    const response = await handler(
      new Request("https://vault.example/api/v1/domains/domain-1/scan", { method: "POST" }),
      { params: Promise.resolve({ id: "domain-1" }) },
    );
    expect(response.status).toBe(401);
    expect(scan).not.toHaveBeenCalled();
  });
});
