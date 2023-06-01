require("dotenv").config();

(async () => {
  const connection = await require("mysql2/promise").createConnection({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USERNAME,
    password: process.env.MYSQL_PASSWORD || undefined,
    database: "app",
    waitForConnections: true,
    connectionLimit: 10,
    maxIdle: 10,
    idleTimeout: 60000,
    queueLimit: 0
  });
  await connection.query("DROP TABLE IF EXISTS users");
})().then(() => process.exit());
