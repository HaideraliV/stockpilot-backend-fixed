import "dotenv/config";
import { pool } from "../src/db.js";

type TableInfo = {
  table_name: string;
  has_business_id: boolean;
  has_user_id: boolean;
};

const emailsRaw = process.env.PURGE_TEST_ADMIN_EMAILS ?? "";
const confirm = (process.env.PURGE_CONFIRM ?? "").trim().toUpperCase();

if (confirm !== "YES") {
  console.log("PURGE_CONFIRM is not YES. Aborting.");
  process.exit(0);
}

const emails = emailsRaw
  .split(",")
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean);

if (emails.length === 0) {
  console.log("No emails provided in PURGE_TEST_ADMIN_EMAILS.");
  process.exit(0);
}

async function listTables(): Promise<TableInfo[]> {
  const result = await pool.query(
    `
    SELECT c.table_name,
           MAX(CASE WHEN c.column_name = 'business_id' THEN 1 ELSE 0 END) AS has_business_id,
           MAX(CASE WHEN c.column_name = 'user_id' THEN 1 ELSE 0 END) AS has_user_id
    FROM information_schema.columns c
    WHERE c.table_schema = 'public'
    GROUP BY c.table_name
    ORDER BY c.table_name
    `
  );
  return result.rows.map((r: any) => ({
    table_name: r.table_name,
    has_business_id: Number(r.has_business_id) === 1,
    has_user_id: Number(r.has_user_id) === 1,
  }));
}

async function purgeAdminByEmail(email: string) {
  const row = await pool.query(
    `SELECT id, business_id FROM users WHERE role='ADMIN' AND email=$1 LIMIT 1`,
    [email]
  );
  const admin = row.rows[0] as { id: string; business_id: string } | undefined;
  if (!admin) {
    console.log(`No admin found for ${email}`);
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const tables = await listTables();
    const counts: Record<string, number> = {};

    const nonCore = tables.filter((t) => !["users", "businesses"].includes(t.table_name));

    for (const t of nonCore) {
      if (!t.has_business_id && !t.has_user_id) continue;

      if (t.has_business_id) {
        const del = await client.query(
          `DELETE FROM "${t.table_name}" WHERE business_id=$1 RETURNING 1`,
          [admin.business_id]
        );
        counts[t.table_name] = (counts[t.table_name] ?? 0) + del.rowCount;
        continue;
      }

      if (t.has_user_id) {
        const del = await client.query(
          `
          DELETE FROM "${t.table_name}"
          WHERE user_id IN (SELECT id FROM users WHERE business_id=$1)
          RETURNING 1
          `,
          [admin.business_id]
        );
        counts[t.table_name] = (counts[t.table_name] ?? 0) + del.rowCount;
      }
    }

    const resets = await client.query(
      `DELETE FROM password_resets WHERE user_id IN (SELECT id FROM users WHERE business_id=$1) RETURNING 1`,
      [admin.business_id]
    );
    counts.password_resets = resets.rowCount;

    const users = await client.query(
      `DELETE FROM users WHERE business_id=$1 RETURNING 1`,
      [admin.business_id]
    );
    counts.users = users.rowCount;

    const biz = await client.query(
      `DELETE FROM businesses WHERE id=$1 RETURNING 1`,
      [admin.business_id]
    );
    counts.businesses = biz.rowCount;

    await client.query("COMMIT");

    console.log(`Purged admin ${email} (business ${admin.business_id})`);
    Object.entries(counts).forEach(([table, count]) => {
      console.log(`  ${table}: ${count}`);
    });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(`Failed to purge ${email}:`, e);
  } finally {
    client.release();
  }
}

async function run() {
  for (const email of emails) {
    await purgeAdminByEmail(email);
  }
  await pool.end();
}

run().catch((e) => {
  console.error("Purge failed:", e);
  process.exit(1);
});
