const mysql = require("mysql2");

require("dotenv").config();

const pool = module.exports = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USERNAME,
  password: process.env.MYSQL_PASSWORD || undefined,
  database: "sso",
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 10,
  idleTimeout: 60000,
  queueLimit: 0
}).promise();

pool.on('connection', function (connection) {
  connection.query('SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE');
});

pool.ready = Promise.all([
    pool.query(`CREATE TABLE IF NOT EXISTS users
              (
                  username    VARCHAR(32)  PRIMARY KEY NOT NULL,
                  output      VARCHAR(100)             NOT NULL,
                  nonce       VARCHAR(100)             NOT NULL,
                  catchphrase VARCHAR(100)             NOT NULL
              )`),
    pool.query(`CREATE TABLE IF NOT EXISTS apps
                (
                    uuid CHAR(36)     PRIMARY KEY NOT NULL,
                    name VARCHAR(32)              NOT NULL,
                    ip   VARCHAR(16)              NOT NULL
                )`),
    pool.query(`CREATE TABLE IF NOT EXISTS credentials
                (
                    username VARCHAR(32)  NOT NULL,
                    uuid     CHAR(36)     NOT NULL,
                    otp      VARCHAR(100) NOT NULL,
                    PRIMARY KEY (username, uuid)
                )`)
]);
