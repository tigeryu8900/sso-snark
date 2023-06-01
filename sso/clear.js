require("dotenv").config();

(async () => {
  const connection = await require("mysql2/promise").createConnection({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USERNAME,
    password: process.env.MYSQL_PASSWORD || undefined,
    database: "sso",
    waitForConnections: true,
    connectionLimit: 10,
    maxIdle: 10,
    idleTimeout: 60000,
    queueLimit: 0
  });
  await connection.query("DROP TABLE IF EXISTS users");
  await connection.query("DROP TABLE IF EXISTS apps");
  await connection.query("DROP TABLE IF EXISTS credentials");
})().then(() => process.exit());
