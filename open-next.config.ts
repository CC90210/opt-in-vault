import { defineCloudflareConfig } from "@opennextjs/cloudflare";

// No incremental cache: consent capture is a write path and certificates are
// per-code, so there is nothing safely cacheable at the edge here.
export default defineCloudflareConfig({});
