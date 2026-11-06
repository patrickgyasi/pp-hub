
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
      const raw = Uint8Array.from(
        binary,
        c => c.charCodeAt(0)
      );

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
      const iv = crypto.getRandomValues(
        new Uint8Array(12)
      );

      const encoded = new TextEncoder().encode(text);

      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoded
      );

      const toBase64 = bytes =>
        btoa(
          String.fromCharCode(
            ...new Uint8Array(bytes)
          )
        );

      return {
        encrypted_token: toBase64(ciphertext),
        iv: toBase64(iv)
      };
    }

    async function decryptText(encrypted, ivText) {
      const key = await getEncryptionKey();

      const fromBase64 = value =>
        Uint8Array.from(
          atob(value),
          c => c.charCodeAt(0)
        );

      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: fromBase64(ivText)
        },
        key,
        fromBase64(encrypted)
      );

      return new TextDecoder().decode(plaintext);
    }

    // 1. Public health check
    if (
      request.method === "GET" &&
      url.pathname === "/health"
    ) {
      return respond({
        service: "PP Hub API",
        status: "online"
      });
    }

    // 2. Initialize original token storage table
    if (
      request.method === "POST" &&
      url.pathname === "/admin/init-db"
    ) {
      if (!requireAdmin()) {
        return respond({ error: "Unauthorized" }, 401);
      }

      if (!env.DB) {
        return respond({
          error: "Database binding missing"
        }, 500);
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
          error: "Encryption test failed"
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
        return respond({
          error: "Database binding missing"
        }, 500);
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
          error: "Token storage test failed"
        }, 500);
      }
    }

    // 5. Prepare encrypted production token storage
    if (
      request.method === "POST" &&
      url.pathname === "/admin/prepare-token-storage"
    ) {
      if (!requireAdmin()) {
        return respond({ error: "Unauthorized" }, 401);
      }

      if (!env.DB || !env.JUMIA_REFRESH_TOKEN) {
        return respond({
          error: "Production configuration incomplete",
          databaseBindingPresent: Boolean(env.DB),
          refreshTokenSecretPresent: Boolean(
            env.JUMIA_REFRESH_TOKEN
          )
        }, 500);
      }

      try {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS jumia_tokens (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            encrypted_refresh_token TEXT NOT NULL,
            refresh_iv TEXT NOT NULL,
            encrypted_access_token TEXT,
            access_iv TEXT,
            access_expires_at TEXT,
            refresh_expires_at TEXT,
            updated_at TEXT NOT NULL
          )
        `).run();

        const existing = await env.DB.prepare(`
          SELECT id
          FROM jumia_tokens
          WHERE id = 1
        `).first();

        let initialized = false;

        if (!existing) {
          const encrypted = await encryptText(
            env.JUMIA_REFRESH_TOKEN
          );

          await env.DB.prepare(`
            INSERT INTO jumia_tokens (
              id,
              encrypted_refresh_token,
              refresh_iv,
              updated_at
            )
            VALUES (1, ?, ?, ?)
          `).bind(
            encrypted.encrypted_token,
            encrypted.iv,
            new Date().toISOString()
          ).run();

          initialized = true;
        }

        return respond({
          success: true,
          database: "D1",
          encryptedStorageReady: true,
          initialTokenStored: initialized,
          existingTokenPreserved: !initialized,
          jumiaContacted: false
        });
      } catch (error) {
        return respond({
          success: false,
          error: "Production token storage preparation failed"
        }, 500);
      }
    }

    // 6. Verify encrypted Jumia token recovery
    if (
      request.method === "POST" &&
      url.pathname === "/admin/verify-token-storage"
    ) {
      if (!requireAdmin()) {
        return respond({ error: "Unauthorized" }, 401);
      }

      if (!env.DB || !env.JUMIA_REFRESH_TOKEN) {
        return respond({
          error: "Required configuration missing"
        }, 500);
      }

      try {
        const saved = await env.DB.prepare(`
          SELECT encrypted_refresh_token, refresh_iv
          FROM jumia_tokens
          WHERE id = 1
        `).first();

        if (!saved) {
          return respond({
            success: false,
            error: "Stored token record not found"
          }, 404);
        }

        const recovered = await decryptText(
          saved.encrypted_refresh_token,
          saved.refresh_iv
        );

        const matchesOriginal =
          recovered === env.JUMIA_REFRESH_TOKEN;

        return respond({
          success: matchesOriginal,
          databaseRecordFound: true,
          decryptionSuccessful: true,
          matchesOriginalSecret: matchesOriginal,
          tokenValueExposed: false,
          jumiaContacted: false
        }, matchesOriginal ? 200 : 409);
      } catch (error) {
        return respond({
          success: false,
          error: "Token recovery verification failed"
        }, 500);
      }
    }

    // 7. Test atomic refresh-lock protection
    if (
      request.method === "POST" &&
      url.pathname === "/admin/test-refresh-lock"
    ) {
      if (!requireAdmin()) {
        return respond({ error: "Unauthorized" }, 401);
      }

      if (!env.DB) {
        return respond({
          error: "Database binding missing"
        }, 500);
      }

      let lockOwner = null;
      let lockAcquired = false;

      try {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS refresh_lock (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            owner TEXT NOT NULL,
            expires_at INTEGER NOT NULL
          )
        `).run();

        const now = Math.floor(Date.now() / 1000);
        lockOwner = crypto.randomUUID();

        const first = await env.DB.prepare(`
          INSERT INTO refresh_lock (id, owner, expires_at)
          VALUES (1, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            owner = excluded.owner,
            expires_at = excluded.expires_at
          WHERE refresh_lock.expires_at <= ?
        `).bind(
          lockOwner,
          now + 90,
          now
        ).run();

        if (first.meta.changes !== 1) {
          throw new Error("First lock acquisition failed");
        }

        lockAcquired = true;

        const secondOwner = crypto.randomUUID();

        const second = await env.DB.prepare(`
          INSERT INTO refresh_lock (id, owner, expires_at)
          VALUES (1, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            owner = excluded.owner,
            expires_at = excluded.expires_at
          WHERE refresh_lock.expires_at <= ?
        `).bind(
          secondOwner,
          now + 90,
          now
        ).run();

        const secondBlocked =
          second.meta.changes === 0;

        if (!secondBlocked) {
          throw new Error("Second lock was not blocked");
        }

        return respond({
          success: true,
          database: "D1",
          firstLockAcquired: true,
          simultaneousLockBlocked: true,
          lockOwnershipVerified: true,
          jumiaContacted: false
        });
      } catch (error) {
        return respond({
          success: false,
          error: "Refresh-lock test failed"
        }, 500);
      } finally {
        if (lockAcquired && lockOwner) {
          await env.DB.prepare(`
            DELETE FROM refresh_lock
            WHERE id = 1 AND owner = ?
          `).bind(lockOwner).run();
        }
      }
    }

    // 8. Jumia Self Authorization preflight
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/refresh-preflight"
    ) {
      if (!requireAdmin()) {
        return respond({ error: "Unauthorized" }, 401);
      }

      if (!env.DB || !env.JUMIA_CLIENT_ID) {
        return respond({
          success: false,
          databaseBindingPresent: Boolean(env.DB),
          clientIdPresent: Boolean(env.JUMIA_CLIENT_ID),
          jumiaContacted: false
        }, 500);
      }

      try {
        const saved = await env.DB.prepare(`
          SELECT encrypted_refresh_token, refresh_iv
          FROM jumia_tokens
          WHERE id = 1
        `).first();

        if (!saved) {
          return respond({
            success: false,
            error: "Encrypted refresh token not found",
            jumiaContacted: false
          }, 404);
        }

        const refreshToken = await decryptText(
          saved.encrypted_refresh_token,
          saved.refresh_iv
        );

        if (!refreshToken) {
          throw new Error("Refresh token is empty");
        }

        const form = new URLSearchParams();

        form.set("grant_type", "refresh_token");
        form.set("client_id", env.JUMIA_CLIENT_ID);
        form.set("refresh_token", refreshToken);

        const fieldsValid =
          form.has("grant_type") &&
          form.has("client_id") &&
          form.has("refresh_token");

        return respond({
          success: fieldsValid,
          authentication: "Jumia Self Authorization",
          endpoint: "https://vendor-api.jumia.com/token",
          method: "POST",
          contentType: "application/x-www-form-urlencoded",
          clientIdPresent: true,
          encryptedRefreshTokenFound: true,
          refreshTokenDecrypted: true,
          requestFieldsValid: fieldsValid,
          clientSecretRequired: false,
          liveRequestSent: false,
          jumiaContacted: false
        });
      } catch (error) {
        return respond({
          success: false,
          error: "Jumia preflight failed",
          jumiaContacted: false
        }, 500);
      }
    }

    // 9. Unknown routes
    return respond({
      error: "Route not found"
    }, 404);
  }
};
