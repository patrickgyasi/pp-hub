
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

    const requireAdmin = () => {
      const authorization = request.headers.get("Authorization");
      return Boolean(
        env.PPHUB_API_KEY &&
        authorization === `Bearer ${env.PPHUB_API_KEY}`
      );
    };

    async function getEncryptionKey() {
      if (!env.PPHUB_TOKEN_ENCRYPTION_KEY) {
        throw new Error("Encryption secret is missing");
      }

      const binary = atob(env.PPHUB_TOKEN_ENCRYPTION_KEY);
      const raw = Uint8Array.from(binary, c => c.charCodeAt(0));

      if (raw.length !== 32) {
        throw new Error("Encryption key must be 32 bytes");
      }

      return crypto.subtle.importKey(
        "raw",
        raw,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
    }

    async function encryptText(text) {
      const key = await getEncryptionKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(text);

      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoded
      );

      const toBase64 = bytes =>
        btoa(String.fromCharCode(...new Uint8Array(bytes)));

      return {
        encrypted_token: toBase64(ciphertext),
        iv: toBase64(iv)
      };
    }

    async function decryptText(encrypted, ivText) {
      const key = await getEncryptionKey();

      const fromBase64 = value =>
        Uint8Array.from(atob(value), c => c.charCodeAt(0));

      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(ivText) },
        key,
        fromBase64(encrypted)
      );

      return new TextDecoder().decode(plaintext);
    }

    // 1. Public health check
    if (request.method === "GET" && url.pathname === "/health") {
      return respond({
        service: "PP Hub API",
        status: "online"
      });
    }

    // 2. Initialize database table
    if (
      request.method === "POST" &&
      url.pathname === "/admin/init-db"
    ) {
      if (!requireAdmin()) {
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

    // 3. Test AES-256-GCM encryption
    if (
      request.method === "POST" &&
      url.pathname === "/admin/test-encryption"
    ) {
      if (!requireAdmin()) {
        return respond({ error: "Unauthorized" }, 401);
      }

      try {
        const testValue = crypto.randomUUID();
        const encrypted = await encryptText(testValue);

        const decrypted = await decryptText(
          encrypted.encrypted_token,
          encrypted.iv
        );

        if (decrypted !== testValue) {
          return respond({
            success: false,
            error: "Encryption verification failed"
          }, 500);
        }

        return respond({
          success: true,
          encryption: "AES-256-GCM",
          keyLength: 256,
          roundTripVerified: true
        });
      } catch (error) {
        return respond({
          success: false,
          error: "Encryption test failed",
          reason: error.message
        }, 500);
      }
    }

    // 4. Test encrypted storage in D1
    if (
      request.method === "POST" &&
      url.pathname === "/admin/test-token-storage"
    ) {
      if (!requireAdmin()) {
        return respond({ error: "Unauthorized" }, 401);
      }

      if (!env.DB) {
        return respond({ error: "Database binding missing" }, 500);
      }

      try {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS encryption_test (
            id INTEGER PRIMARY KEY,
            encrypted_token TEXT NOT NULL,
            iv TEXT NOT NULL,
            updated_at TEXT NOT NULL
          )
        `).run();

        const testValue = crypto.randomUUID();
        const encrypted = await encryptText(testValue);

        await env.DB.prepare(`
          INSERT INTO encryption_test
          (id, encrypted_token, iv, updated_at)
          VALUES (1, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            encrypted_token = excluded.encrypted_token,
            iv = excluded.iv,
            updated_at = excluded.updated_at
        `).bind(
          encrypted.encrypted_token,
          encrypted.iv,
          new Date().toISOString()
        ).run();

        const saved = await env.DB.prepare(`
          SELECT encrypted_token, iv
          FROM encryption_test
          WHERE id = 1
        `).first();

        if (!saved) {
          throw new Error("Saved record not found");
        }

        const decrypted = await decryptText(
          saved.encrypted_token,
          saved.iv
        );

        if (decrypted !== testValue) {
          throw new Error("Database verification failed");
        }

        await env.DB.prepare(`
          DELETE FROM encryption_test WHERE id = 1
        `).run();

        return respond({
          success: true,
          database: "D1",
          encryption: "AES-256-GCM",
          recordSaved: true,
          recordRetrieved: true,
          roundTripVerified: true,
          testRecordDeleted: true
        });

      } catch (error) {
        return respond({
          success: false,
          error: "Token storage test failed",
          reason: error.message
        }, 500);
      }
    }

    // 5. Unknown routes
    return respond({ error: "Route not found" }, 404);
  }
};
