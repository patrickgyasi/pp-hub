
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const respond = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store"
        }
      });

    if (request.method === "GET" && url.pathname === "/health") {
      return respond({
        service: "PP Hub API",
        status: "online"
      });
    }

    if (
      request.method === "POST" &&
      url.pathname === "/admin/init-db"
    ) {
      const authorization = request.headers.get("Authorization");

      if (
        !env.PPHUB_API_KEY ||
        authorization !== `Bearer ${env.PPHUB_API_KEY}`
      ) {
        return respond({ error: "Unauthorized" }, 401);
      }

      if (!env.DB) {
        return respond({ error: "Database binding missing" }, 500);
      }

      try {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS token_store (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            encrypted_token TEXT NOT NULL,
            iv TEXT NOT NULL,
            salt TEXT NOT NULL,
            updated_at TEXT NOT NULL
          )
        `).run();

        return respond({
          success: true,
          message: "Token storage table is ready."
        });
      } catch (error) {
        return respond({
          error: "Database initialization failed"
        }, 500);
      }
    }

    return respond({ error: "Route not found" }, 404);
  }
};
