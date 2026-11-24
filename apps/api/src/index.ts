import { Hono } from "hono";

export function createPlaceholderApp(): Hono {
  const app = new Hono();
  app.get("/api/health", (c) => c.json({ ok: true, service: "vpsagent-api" }));
  return app;
}
