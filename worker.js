
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

    const requireAdmin = () =>
      Boolean(
        env.PPHUB_API_KEY &&
        request.headers.get("Authorization") ===
          `Bearer ${env.PPHUB_API_KEY}`
      );

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

    async function encryptText(value) {
      const key = await getEncryptionKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(value);

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

    // All remaining admin routes require authentication.
    if (
      url.pathname.startsWith("/admin/") &&
      !requireAdmin()
    ) {
      return respond({
        error: "Unauthorized"
      }, 401);
    }

    // 2. Initialize original token storage
    if (
      request.method === "POST" &&
      url.pathname === "/admin/init-db"
    ) {
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
      } catch {
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
      try {
        const testValue = crypto.randomUUID();
        const encrypted = await encryptText(testValue);

        const decrypted = await decryptText(
          encrypted.encrypted_token,
          encrypted.iv
        );

        if (decrypted !== testValue) {
          throw new Error("Encryption verification failed");
        }

        return respond({
          success: true,
          encryption: "AES-256-GCM",
          keyLength: 256,
          roundTripVerified: true
        });
      } catch {
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
          INSERT INTO encryption_test (
            id,
            encrypted_token,
            iv,
            updated_at
          )
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
          DELETE FROM encryption_test
          WHERE id = 1
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
      } catch {
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
      } catch {
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
      } catch {
        return respond({
          success: false,
          error: "Token recovery verification failed"
        }, 500);
      }
    }

    // 7. Test refresh-lock protection
    if (
      request.method === "POST" &&
      url.pathname === "/admin/test-refresh-lock"
    ) {
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
          INSERT INTO refresh_lock (
            id,
            owner,
            expires_at
          )
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

        const second = await env.DB.prepare(`
          INSERT INTO refresh_lock (
            id,
            owner,
            expires_at
          )
          VALUES (1, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            owner = excluded.owner,
            expires_at = excluded.expires_at
          WHERE refresh_lock.expires_at <= ?
        `).bind(
          crypto.randomUUID(),
          now + 90,
          now
        ).run();

        if (second.meta.changes !== 0) {
          throw new Error("Second lock was not blocked");
        }

        return respond({
          success: true,
          database: "D1",
          firstLockAcquired: true,
          secondLockBlocked: true,
          ownershipVerified: true,
          jumiaContacted: false
        });
      } catch {
        return respond({
          success: false,
          error: "Refresh-lock test failed"
        }, 500);
      } finally {
        if (lockAcquired && lockOwner) {
          try {
            await env.DB.prepare(`
              DELETE FROM refresh_lock
              WHERE id = 1
                AND owner = ?
            `).bind(lockOwner).run();
          } catch {
            // Preserve the original test result.
          }
        }
      }
    }

    // 8. Jumia Self Authorization preflight
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/refresh-preflight"
    ) {
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
      } catch {
        return respond({
          success: false,
          error: "Jumia preflight failed",
          jumiaContacted: false
        }, 500);
      }
    }

    // 9. Prepare fail-safe Jumia refresh control
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/prepare-refresh-control"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing"
        }, 500);
      }

      try {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS jumia_refresh_control (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            state TEXT NOT NULL CHECK (
              state IN ('ready', 'in_progress', 'uncertain')
            ),
            operation_id TEXT,
            started_at TEXT,
            updated_at TEXT NOT NULL
          )
        `).run();

        await env.DB.prepare(`
          INSERT INTO jumia_refresh_control (
            id,
            state,
            updated_at
          )
          VALUES (1, 'ready', ?)
          ON CONFLICT(id) DO NOTHING
        `).bind(new Date().toISOString()).run();

        const control = await env.DB.prepare(`
          SELECT state, operation_id, started_at, updated_at
          FROM jumia_refresh_control
          WHERE id = 1
        `).first();

        if (!control) {
          throw new Error("Refresh control record missing");
        }

        return respond({
          success: true,
          database: "D1",
          refreshControlTableReady: true,
          state: control.state,
          operationInProgress:
            control.state === "in_progress",
          manualRecoveryRequired:
            control.state === "uncertain",
          jumiaContacted: false
        });
      } catch {
        return respond({
          success: false,
          error: "Refresh control preparation failed",
          jumiaContacted: false
        }, 500);
      }
    }

    // 10. Protected Jumia live token refresh
    // Keep JUMIA_LIVE_REFRESH_ENABLED unset.
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/refresh"
    ) {
      if (env.JUMIA_LIVE_REFRESH_ENABLED !== "true") {
        return respond({
          success: false,
          error: "Live Jumia refresh is disabled",
          liveRequestSent: false,
          jumiaContacted: false
        }, 423);
      }

      if (!env.DB || !env.JUMIA_CLIENT_ID) {
        return respond({
          success: false,
          error: "Required configuration missing",
          liveRequestSent: false,
          jumiaContacted: false
        }, 500);
      }

      const operationId = crypto.randomUUID();
      const startedAt = new Date().toISOString();
      let requestSent = false;

      try {
        const acquired = await env.DB.prepare(`
          UPDATE jumia_refresh_control
          SET
            state = 'in_progress',
            operation_id = ?,
            started_at = ?,
            updated_at = ?
          WHERE id = 1
            AND state = 'ready'
            AND EXISTS (
              SELECT 1
              FROM jumia_tokens
              WHERE id = 1
            )
        `).bind(
          operationId,
          startedAt,
          startedAt
        ).run();

        if (acquired.meta.changes !== 1) {
          const current = await env.DB.prepare(`
            SELECT state
            FROM jumia_refresh_control
            WHERE id = 1
          `).first();

          return respond({
            success: false,
            error: "Refresh control is not ready",
            currentState: current?.state || "missing",
            liveRequestSent: false,
            jumiaContacted: false
          }, 409);
        }

        const saved = await env.DB.prepare(`
          SELECT encrypted_refresh_token, refresh_iv
          FROM jumia_tokens
          WHERE id = 1
        `).first();

        if (!saved) {
          throw new Error("Stored refresh token not found");
        }

        const refreshToken = await decryptText(
          saved.encrypted_refresh_token,
          saved.refresh_iv
        );

        if (!refreshToken) {
          throw new Error("Stored refresh token is empty");
        }

        const form = new URLSearchParams();
        form.set("grant_type", "refresh_token");
        form.set("client_id", env.JUMIA_CLIENT_ID);
        form.set("refresh_token", refreshToken);

        requestSent = true;

        const jumiaResponse = await fetch(
          "https://vendor-api.jumia.com/token",
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded",
              "Accept": "application/json"
            },
            body: form.toString()
          }
        );

        if (!jumiaResponse.ok) {
          throw new Error(
            `Jumia returned HTTP ${jumiaResponse.status}`
          );
        }

        const tokenData = await jumiaResponse.json();

        const expiresIn = Number(tokenData.expires_in);
        const refreshExpiresIn = Number(
          tokenData.refresh_expires_in
        );

        if (
          typeof tokenData.access_token !== "string" ||
          !tokenData.access_token ||
          typeof tokenData.refresh_token !== "string" ||
          !tokenData.refresh_token ||
          !Number.isFinite(expiresIn) ||
          expiresIn <= 0 ||
          !Number.isFinite(refreshExpiresIn) ||
          refreshExpiresIn <= 0
        ) {
          throw new Error(
            "Jumia token response validation failed"
          );
        }

        const encryptedAccess = await encryptText(
          tokenData.access_token
        );

        const encryptedRefresh = await encryptText(
          tokenData.refresh_token
        );

        const completedAt = new Date();
        const completedAtText = completedAt.toISOString();

        const accessExpiresAt = new Date(
          completedAt.getTime() + expiresIn * 1000
        ).toISOString();

        const refreshExpiresAt = new Date(
          completedAt.getTime() +
            refreshExpiresIn * 1000
        ).toISOString();

        let persisted = false;

        for (let attempt = 1; attempt <= 3; attempt++) {
          try {
            const results = await env.DB.batch([
              env.DB.prepare(`
                UPDATE jumia_tokens
                SET
                  encrypted_refresh_token = ?,
                  refresh_iv = ?,
                  encrypted_access_token = ?,
                  access_iv = ?,
                  access_expires_at = ?,
                  refresh_expires_at = ?,
                  updated_at = ?
                WHERE id = 1
              `).bind(
                encryptedRefresh.encrypted_token,
                encryptedRefresh.iv,
                encryptedAccess.encrypted_token,
                encryptedAccess.iv,
                accessExpiresAt,
                refreshExpiresAt,
                completedAtText
              ),

              env.DB.prepare(`
                UPDATE jumia_refresh_control
                SET
                  state = 'ready',
                  operation_id = NULL,
                  started_at = NULL,
                  updated_at = ?
                WHERE id = 1
                  AND state = 'in_progress'
                  AND operation_id = ?
              `).bind(
                completedAtText,
                operationId
              )
            ]);

            if (
              results[0].meta.changes === 1 &&
              results[1].meta.changes === 1
            ) {
              persisted = true;
              break;
            }
          } catch {
            // Retry while replacement tokens remain in memory.
          }
        }

        if (!persisted) {
          throw new Error(
            "Token persistence was not confirmed"
          );
        }

        return respond({
          success: true,
          accessTokenStored: true,
          refreshTokenRotatedAndStored: true,
          accessTokenExpiresAt: accessExpiresAt,
          refreshTokenExpiresAt: refreshExpiresAt,
          refreshControlState: "ready",
          tokenValuesExposed: false,
          liveRequestSent: true,
          jumiaContacted: true
        });

      } catch {
        try {
          await env.DB.prepare(`
            UPDATE jumia_refresh_control
            SET
              state = 'uncertain',
              updated_at = ?
            WHERE id = 1
              AND state = 'in_progress'
              AND operation_id = ?
          `).bind(
            new Date().toISOString(),
            operationId
          ).run();
        } catch {
          // Existing in_progress state blocks another refresh.
        }

        return respond({
          success: false,
          error:
            "Jumia refresh could not be safely completed",
          refreshControlState:
            "uncertain_or_in_progress",
          liveRequestSent: requestSent,
          jumiaContacted: requestSent,
          manualRecoveryRequired: requestSent
        }, 502);
      }
    }

    // 11. Test concurrency and dummy-token persistence
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/test-refresh-safety"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing"
        }, 500);
      }

      const ownerA = crypto.randomUUID();
      const ownerB = crypto.randomUUID();
      const testId = crypto.randomUUID();

      let acquiredOwner = null;
      let testRecordCreated = false;

      try {
        const current = await env.DB.prepare(`
          SELECT state
          FROM jumia_refresh_control
          WHERE id = 1
        `).first();

        if (!current || current.state !== "ready") {
          return respond({
            success: false,
            error:
              "Refresh control must be ready before testing",
            currentState: current?.state || "missing",
            jumiaContacted: false
          }, 409);
        }

        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS
          jumia_token_persistence_test (
            id TEXT PRIMARY KEY,
            encrypted_access_token TEXT NOT NULL,
            access_iv TEXT NOT NULL,
            encrypted_refresh_token TEXT NOT NULL,
            refresh_iv TEXT NOT NULL,
            created_at TEXT NOT NULL
          )
        `).run();

        const acquire = owner =>
          env.DB.prepare(`
            UPDATE jumia_refresh_control
            SET
              state = 'in_progress',
              operation_id = ?,
              started_at = ?,
              updated_at = ?
            WHERE id = 1
              AND state = 'ready'
          `).bind(
            owner,
            new Date().toISOString(),
            new Date().toISOString()
          ).run();

        const attempts = await Promise.all([
          acquire(ownerA),
          acquire(ownerB)
        ]);

        const changesA = attempts[0].meta.changes;
        const changesB = attempts[1].meta.changes;

        if (
          changesA + changesB !== 1 ||
          ![0, 1].includes(changesA) ||
          ![0, 1].includes(changesB)
        ) {
          throw new Error(
            "Concurrent control test failed"
          );
        }

        acquiredOwner =
          changesA === 1 ? ownerA : ownerB;

        const dummyAccess =
          `TEST_ACCESS_${crypto.randomUUID()}`;

        const dummyRefresh =
          `TEST_REFRESH_${crypto.randomUUID()}`;

        const encryptedAccess =
          await encryptText(dummyAccess);

        const encryptedRefresh =
          await encryptText(dummyRefresh);

        await env.DB.prepare(`
          INSERT INTO jumia_token_persistence_test (
            id,
            encrypted_access_token,
            access_iv,
            encrypted_refresh_token,
            refresh_iv,
            created_at
          )
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          testId,
          encryptedAccess.encrypted_token,
          encryptedAccess.iv,
          encryptedRefresh.encrypted_token,
          encryptedRefresh.iv,
          new Date().toISOString()
        ).run();

        testRecordCreated = true;

        const saved = await env.DB.prepare(`
          SELECT
            encrypted_access_token,
            access_iv,
            encrypted_refresh_token,
            refresh_iv
          FROM jumia_token_persistence_test
          WHERE id = ?
        `).bind(testId).first();

        if (!saved) {
          throw new Error(
            "Dummy token record not found"
          );
        }

        const recoveredAccess = await decryptText(
          saved.encrypted_access_token,
          saved.access_iv
        );

        const recoveredRefresh = await decryptText(
          saved.encrypted_refresh_token,
          saved.refresh_iv
        );

        if (
          recoveredAccess !== dummyAccess ||
          recoveredRefresh !== dummyRefresh
        ) {
          throw new Error(
            "Dummy token recovery failed"
          );
        }

        return respond({
          success: true,
          concurrencyTest: {
            firstRequestAcquired: true,
            secondRequestBlocked: true,
            onlyOneOwnerAcquired: true
          },
          persistenceTest: {
            dummyAccessTokenStored: true,
            dummyRefreshTokenStored: true,
            accessTokenDecrypted: true,
            refreshTokenDecrypted: true,
            valuesMatched: true
          },
          realTokensChanged: false,
          jumiaContacted: false
        });

      } catch {
        return respond({
          success: false,
          error: "Refresh safety test failed",
          jumiaContacted: false
        }, 500);

      } finally {
        if (testRecordCreated) {
          try {
            await env.DB.prepare(`
              DELETE FROM jumia_token_persistence_test
              WHERE id = ?
            `).bind(testId).run();
          } catch {
            // Test record cleanup can be retried separately.
          }
        }

        if (acquiredOwner) {
          try {
            await env.DB.prepare(`
              UPDATE jumia_refresh_control
              SET
                state = 'ready',
                operation_id = NULL,
                started_at = NULL,
                updated_at = ?
              WHERE id = 1
                AND state = 'in_progress'
                AND operation_id = ?
            `).bind(
              new Date().toISOString(),
              acquiredOwner
            ).run();
          } catch {
            // Do not overwrite another operation's state.
          }
        }
      }
    }

    // 12. Test isolated encrypted recovery storage.
    if (
      request.method === "POST" &&
      url.pathname ===
        "/admin/jumia/test-recovery-storage"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing",
          jumiaContacted: false
        }, 500);
      }

      const testId = crypto.randomUUID();
      const dummyToken =
        `PPHUB_DUMMY_RECOVERY_${testId}`;

      let testRecordStored = false;
      let cleanupVerified = false;

      try {
        const table = await env.DB.prepare(`
          SELECT name
          FROM sqlite_master
          WHERE type = 'table'
            AND name = 'jumia_pending_recovery'
        `).first();

        if (!table) {
          return respond({
            success: false,
            error: "Recovery table does not exist",
            jumiaContacted: false
          }, 404);
        }

        const existing = await env.DB.prepare(`
          SELECT id
          FROM jumia_pending_recovery
          WHERE id = 1
        `).first();

        if (existing) {
          return respond({
            success: false,
            error:
              "A real pending recovery record already exists",
            testStarted: false,
            existingRecordPreserved: true,
            jumiaContacted: false
          }, 409);
        }

        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS
          jumia_recovery_test (
            id TEXT PRIMARY KEY,
            encrypted_refresh_token TEXT NOT NULL,
            refresh_iv TEXT NOT NULL,
            created_at TEXT NOT NULL
          )
        `).run();

        const encrypted = await encryptText(dummyToken);

        await env.DB.prepare(`
          INSERT INTO jumia_recovery_test (
            id,
            encrypted_refresh_token,
            refresh_iv,
            created_at
          )
          VALUES (?, ?, ?, ?)
        `).bind(
          testId,
          encrypted.encrypted_token,
          encrypted.iv,
          new Date().toISOString()
        ).run();

        testRecordStored = true;

        const saved = await env.DB.prepare(`
          SELECT
            encrypted_refresh_token,
            refresh_iv
          FROM jumia_recovery_test
          WHERE id = ?
        `).bind(testId).first();

        if (!saved) {
          throw new Error(
            "Recovery test record not found"
          );
        }

        const recovered = await decryptText(
          saved.encrypted_refresh_token,
          saved.refresh_iv
        );

        if (recovered !== dummyToken) {
          throw new Error(
            "Recovery verification failed"
          );
        }

        await env.DB.prepare(`
          DELETE FROM jumia_recovery_test
          WHERE id = ?
        `).bind(testId).run();

        testRecordStored = false;

        const remaining = await env.DB.prepare(`
          SELECT id
          FROM jumia_recovery_test
          WHERE id = ?
        `).bind(testId).first();

        cleanupVerified = !remaining;

        if (!cleanupVerified) {
          throw new Error(
            "Test cleanup could not be verified"
          );
        }

        return respond({
          success: true,
          recoveryStorageTest: {
            dummyTokenGenerated: true,
            encryptionSuccessful: true,
            databaseStorageSuccessful: true,
            databaseRetrievalSuccessful: true,
            decryptionSuccessful: true,
            recoveredValueMatched: true,
            testRecordDeleted: true,
            cleanupVerified: true
          },
          activeTokenChanged: false,
          realPendingRecoveryRecordChanged: false,
          refreshControlChanged: false,
          jumiaContacted: false,
          tokenValueExposed: false
        });

      } catch {
        return respond({
          success: false,
          error: "Recovery storage test failed",
          testRecordMayRemain: testRecordStored,
          cleanupVerified,
          jumiaContacted: false,
          tokenValueExposed: false
        }, 500);
      }
    }

    // 13. Safely stage a replacement Jumia refresh token.
    if (
      request.method === "POST" &&
      url.pathname ===
        "/admin/jumia/stage-recovery-token"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing"
        }, 500);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return respond({
          success: false,
          error: "A valid JSON body is required",
          tokenStored: false
        }, 400);
      }

      if (
        !body ||
        body.confirm !== "STAGE_REPLACEMENT_TOKEN" ||
        typeof body.refresh_token !== "string" ||
        !body.refresh_token.trim()
      ) {
        return respond({
          success: false,
          error:
            "Replacement token and confirmation required",
          tokenStored: false
        }, 400);
      }

      try {
        const control = await env.DB.prepare(`
          SELECT state
          FROM jumia_refresh_control
          WHERE id = 1
        `).first();

        if (
          !control ||
          control.state !== "uncertain"
        ) {
          return respond({
            success: false,
            error: "Refresh control must be uncertain",
            currentState: control?.state || "missing",
            tokenStored: false
          }, 409);
        }

        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS
          jumia_pending_recovery (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            encrypted_refresh_token TEXT NOT NULL,
            refresh_iv TEXT NOT NULL,
            created_at TEXT NOT NULL
          )
        `).run();

        const existing = await env.DB.prepare(`
          SELECT id
          FROM jumia_pending_recovery
          WHERE id = 1
        `).first();

        if (existing) {
          return respond({
            success: false,
            error:
              "A pending recovery token already exists",
            tokenStored: false,
            manualReviewRequired: true,
            jumiaContacted: false
          }, 409);
        }

        const encrypted = await encryptText(
          body.refresh_token.trim()
        );

        await env.DB.prepare(`
          INSERT INTO jumia_pending_recovery (
            id,
            encrypted_refresh_token,
            refresh_iv,
            created_at
          )
          VALUES (1, ?, ?, ?)
        `).bind(
          encrypted.encrypted_token,
          encrypted.iv,
          new Date().toISOString()
        ).run();

        return respond({
          success: true,
          pendingRecoveryTokenStored: true,
          encrypted: true,
          activeTokenChanged: false,
          refreshControlState: "uncertain",
          tokenValueExposed: false,
          tokenVerifiedWithJumia: false,
          jumiaContacted: false
        });

      } catch {
        return respond({
          success: false,
          error: "Recovery token staging failed",
          tokenValueExposed: false,
          jumiaContacted: false
        }, 500);
      }
    }

    // 14. Start a Jumia refresh operation journal record.
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/operation/start"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing"
        }, 500);
      }

      try {
        const operationId = crypto.randomUUID();
        const now = new Date().toISOString();

        await env.DB.prepare(`
          INSERT INTO jumia_refresh_operations (
            operation_id,
            status,
            started_at,
            created_at,
            updated_at
          )
          VALUES (?, 'prepared', ?, ?, ?)
        `).bind(
          operationId,
          now,
          now,
          now
        ).run();

        return respond({
          success: true,
          operationId,
          status: "prepared",
          created: true,
          jumiaContacted: false
        }, 201);
      } catch {
        return respond({
          success: false,
          error: "Operation journal creation failed",
          jumiaContacted: false
        }, 500);
      }
    }

    // 15. Read operation status.
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/operation/status"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing"
        }, 500);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return respond({
          success: false,
          error: "Valid JSON body required"
        }, 400);
      }

      if (
        !body ||
        typeof body.operation_id !== "string" ||
        !body.operation_id.trim()
      ) {
        return respond({
          success: false,
          error: "operation_id is required"
        }, 400);
      }

      try {
        const operation = await env.DB.prepare(`
          SELECT
            operation_id,
            status,
            started_at,
            request_sent_at,
            response_received_at,
            persistence_confirmed_at,
            completed_at,
            http_status,
            error_code,
            created_at,
            updated_at
          FROM jumia_refresh_operations
          WHERE operation_id = ?
        `).bind(body.operation_id.trim()).first();

        if (!operation) {
          return respond({
            success: false,
            error: "Operation not found"
          }, 404);
        }

        return respond({
          success: true,
          operation,
          jumiaContacted: false
        });
      } catch {
        return respond({
          success: false,
          error: "Operation status lookup failed"
        }, 500);
      }
    }

    // 16. Mark an operation as uncertain.
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/operation/mark-uncertain"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing"
        }, 500);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return respond({
          success: false,
          error: "Valid JSON body required"
        }, 400);
      }

      if (
        !body ||
        typeof body.operation_id !== "string" ||
        !body.operation_id.trim()
      ) {
        return respond({
          success: false,
          error: "operation_id is required"
        }, 400);
      }

      try {
        const now = new Date().toISOString();

        const result = await env.DB.prepare(`
          UPDATE jumia_refresh_operations
          SET
            status = 'uncertain',
            error_code = 'MANUAL_UNCERTAIN',
            updated_at = ?
          WHERE operation_id = ?
            AND status IN (
              'prepared',
              'request_sent',
              'response_received'
            )
        `).bind(
          now,
          body.operation_id.trim()
        ).run();

        if (result.meta.changes !== 1) {
          const current = await env.DB.prepare(`
            SELECT status
            FROM jumia_refresh_operations
            WHERE operation_id = ?
          `).bind(body.operation_id.trim()).first();

          if (!current) {
            return respond({
              success: false,
              error: "Operation not found"
            }, 404);
          }

          return respond({
            success: false,
            error:
              "Operation cannot be marked uncertain from its current status",
            currentStatus: current.status
          }, 409);
        }

        return respond({
          success: true,
          operationId: body.operation_id.trim(),
          status: "uncertain",
          journalUpdated: true,
          activeTokenChanged: false,
          refreshControlChanged: false,
          jumiaContacted: false
        });
      } catch {
        return respond({
          success: false,
          error: "Could not update operation journal"
        }, 500);
      }
    }

    // 17. Controlled operation lifecycle transition.
    // This updates the journal only; it never contacts Jumia.
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/operation/transition"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing"
        }, 500);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return respond({
          success: false,
          error: "Valid JSON body required"
        }, 400);
      }

      const operationId =
        typeof body?.operation_id === "string"
          ? body.operation_id.trim()
          : "";

      const nextStatus = body?.next_status;

      const allowedTransitions = {
        prepared: ["request_sent", "uncertain", "failed"],
        request_sent: ["response_received", "uncertain", "failed"],
        response_received: ["persisted", "uncertain", "failed"]
      };

      if (
        !operationId ||
        ![
          "request_sent",
          "response_received",
          "persisted",
          "uncertain",
          "failed"
        ].includes(nextStatus)
      ) {
        return respond({
          success: false,
          error: "Valid operation_id and next_status are required"
        }, 400);
      }

      if (
        body.http_status !== undefined &&
        (
          !Number.isInteger(body.http_status) ||
          body.http_status < 100 ||
          body.http_status > 599
        )
      ) {
        return respond({
          success: false,
          error: "http_status must be a valid HTTP status code"
        }, 400);
      }

      if (
        body.error_code !== undefined &&
        (
          typeof body.error_code !== "string" ||
          body.error_code.length > 100
        )
      ) {
        return respond({
          success: false,
          error: "Invalid error_code"
        }, 400);
      }

      try {
        const current = await env.DB.prepare(`
          SELECT status
          FROM jumia_refresh_operations
          WHERE operation_id = ?
        `).bind(operationId).first();

        if (!current) {
          return respond({
            success: false,
            error: "Operation not found"
          }, 404);
        }

        const permitted =
          allowedTransitions[current.status] || [];

        if (!permitted.includes(nextStatus)) {
          return respond({
            success: false,
            error: "Invalid operation status transition",
            currentStatus: current.status,
            requestedStatus: nextStatus,
            permittedNextStatuses: permitted
          }, 409);
        }

        const now = new Date().toISOString();

        const timestampColumn = {
          request_sent: "request_sent_at",
          response_received: "response_received_at",
          persisted: "persistence_confirmed_at"
        }[nextStatus];

        const completed = [
          "persisted",
          "uncertain",
          "failed"
        ].includes(nextStatus);

        const update = await env.DB.prepare(`
          UPDATE jumia_refresh_operations
          SET
            status = ?,
            request_sent_at = CASE
              WHEN ? = 'request_sent' THEN ?
              ELSE request_sent_at
            END,
            response_received_at = CASE
              WHEN ? = 'response_received' THEN ?
              ELSE response_received_at
            END,
            persistence_confirmed_at = CASE
              WHEN ? = 'persisted' THEN ?
              ELSE persistence_confirmed_at
            END,
            completed_at = CASE
              WHEN ? = 1 THEN ?
              ELSE completed_at
            END,
            http_status = COALESCE(?, http_status),
            error_code = COALESCE(?, error_code),
            updated_at = ?
          WHERE operation_id = ?
            AND status = ?
        `).bind(
          nextStatus,
          nextStatus, now,
          nextStatus, now,
          nextStatus, now,
          completed ? 1 : 0, now,
          body.http_status ?? null,
          body.error_code ?? null,
          now,
          operationId,
          current.status
        ).run();

        if (update.meta.changes !== 1) {
          return respond({
            success: false,
            error: "Operation changed before update; retrieve its latest status"
          }, 409);
        }

        return respond({
          success: true,
          operationId,
          previousStatus: current.status,
          status: nextStatus,
          journalUpdated: true,
          jumiaContacted: false
        });

      } catch {
        return respond({
          success: false,
          error: "Operation transition failed",
          jumiaContacted: false
        }, 500);
      }
    
}
    
    // 18. JTRE: Promote staged recovery token.
    // This performs local integrity checks only.
    // It does not contact Jumia or release refresh control.
    if (
      request.method === "POST" &&
      url.pathname === "/admin/jumia/recovery/promote"
    ) {
      if (!env.DB) {
        return respond({
          success: false,
          error: "Database binding missing",
          jumiaContacted: false
        }, 500);
      }

      try {
        const control = await env.DB.prepare(`
          SELECT state
          FROM jumia_refresh_control
          WHERE id = 1
        `).first();

        if (!control || control.state !== "uncertain") {
          return respond({
            success: false,
            error: "Refresh control must be uncertain",
            currentState: control?.state || "missing",
            promoted: false,
            jumiaContacted: false
          }, 409);
        }

        const pending = await env.DB.prepare(`
          SELECT
            encrypted_refresh_token,
            refresh_iv
          FROM jumia_pending_recovery
          WHERE id = 1
        `).first();

        if (!pending) {
          return respond({
            success: false,
            error: "Pending recovery token not found",
            promoted: false,
            jumiaContacted: false
          }, 404);
        }

        const recoveredToken = await decryptText(
          pending.encrypted_refresh_token,
          pending.refresh_iv
        );

        if (
          typeof recoveredToken !== "string" ||
          !recoveredToken.trim()
        ) {
          throw new Error("Recovery token integrity check failed");
        }

        const active = await env.DB.prepare(`
          SELECT id
          FROM jumia_tokens
          WHERE id = 1
        `).first();

        if (!active) {
          return respond({
            success: false,
            error: "Active token storage record not found",
            promoted: false,
            jumiaContacted: false
          }, 409);
        }

        const now = new Date().toISOString();

        const result = await env.DB.prepare(`
          UPDATE jumia_tokens
          SET
            encrypted_refresh_token = ?,
            refresh_iv = ?,
            encrypted_access_token = NULL,
            access_iv = NULL,
            access_expires_at = NULL,
            refresh_expires_at = NULL,
            updated_at = ?
          WHERE id = 1
            AND EXISTS (
              SELECT 1
              FROM jumia_refresh_control
              WHERE id = 1
                AND state = 'uncertain'
            )
            AND EXISTS (
              SELECT 1
              FROM jumia_pending_recovery
              WHERE id = 1
                AND encrypted_refresh_token = ?
                AND refresh_iv = ?
            )
        `).bind(
          pending.encrypted_refresh_token,
          pending.refresh_iv,
          now,
          pending.encrypted_refresh_token,
          pending.refresh_iv
        ).run();

        if (result.meta.changes !== 1) {
          return respond({
            success: false,
            error: "Promotion was not confirmed",
            promoted: false,
            refreshControlState: "uncertain",
            jumiaContacted: false
          }, 409);
        }

        return respond({
          success: true,
          promoted: true,
          localIntegrityVerified: true,
          pendingRecoveryPreserved: true,
          activeTokenChanged: true,
          refreshControlState: "uncertain",
          tokenValueExposed: false,
          tokenVerifiedWithJumia: false,
          jumiaContacted: false
        });

      } catch {
        return respond({
          success: false,
          error: "Recovery token promotion failed",
          refreshControlState: "uncertain",
          jumiaContacted: false,
          tokenValueExposed: false
        }, 500);
      }
    }

    // 18. Unknown routes
    return respond({
      error: "Route not found"
    }, 404);
  }
};
