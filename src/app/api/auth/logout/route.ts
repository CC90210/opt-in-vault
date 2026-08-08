import { SESSION_COOKIE_NAME } from "@/server/auth/session";

import { createLogoutHandler } from "./handler";

const handler = createLogoutHandler(SESSION_COOKIE_NAME);

export async function POST(request: Request): Promise<Response> {
  return handler(request);
}
