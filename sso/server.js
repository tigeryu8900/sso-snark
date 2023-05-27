const express = require("express");
const path = require("path");
const mysql = require("mysql2");
const snarkjs = require("snarkjs");
const fs = require("fs");
const randomWords = require('random-words');

require("dotenv").config();

const vKey = JSON.parse(fs.readFileSync("../verification_key.json").toString());

(async () => {
  const snarkjspath = path.join(path.dirname(require.resolve('snarkjs')), "snarkjs.js");

  function generateNonce() {
    return crypto.getRandomValues(new BigUint64Array(1))[0].toString();
  }

  const pool = mysql.createPool({
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

  await pool.query(`CREATE TABLE IF NOT EXISTS USERS
             (
                 USERNAME    VARCHAR(32)  PRIMARY KEY NOT NULL,
                 OUTPUT      VARCHAR(100)             NOT NULL,
                 NONCE       VARCHAR(100)             NOT NULL,
                 CATCHPHRASE VARCHAR(100)             NOT NULL
             )`);

  const app = express();
  const port = 3000;

  app.use(express.json());
  app.use(express.urlencoded({extended: true}));
  app.use(require("cookie-parser")());
  app.use(require("express-session")({
    secret: "tigerthegreat",
    saveUninitialized: false,
    cookie: {maxAge: 1000 * 60 * 60 * 24},
    resave: false
  }));

  app.get("/api/catchphrase", async ({session}, res) => {
    if (session.username) {
      let [[{CATCHPHRASE}]] = await pool.query("SELECT CATCHPHRASE FROM USERS WHERE USERNAME = ?", [session.username]);
      res.send(CATCHPHRASE);
    } else {
      res.status(403);
      res.send("Forbidden");
    }
  });

  app.get("/", ({session}, res) => {
    if (session.username) {
      res.sendFile("index.html", { root: __dirname });
    } else {
      res.redirect("/signin");
    }
  });

  app.get("/api/nonce", ({session}, res) => {
    session.nonce = generateNonce();
    res.send(session.nonce);
  });

  app.get("/register", ({session, query}, res) => {
    res.sendFile("register.html", {root: __dirname});
  });

  app.post("/register", async ({body, session}, res) => {
    console.log('test');
    // const connection = await getConnection();
    // const connection = await pool.promise().getConnection();
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      console.log("begin transaction");
      // await connection.query("LOCK TABLES `USERS` WRITE");
      if (body.username === "users") {
        console.error("'users' is reserved.");
        res.redirect(400, "/register?message='users'+is+reserved.");
        await connection.rollback();
        return;
      }
      try {
        BigInt(body.output);
        BigInt(body.nonce);
      } catch (e) {
        console.error("invalid public signals");
        res.redirect(400, "/register?message=Invalid+public+signals.");
        await connection.rollback();
        return;
      }
      if (!session.nonce) {
        console.error("nonce not generated");
        res.redirect(500, "/register?message=Nonce+not+generated.");
        await connection.rollback();
        return;
      }
      if (BigInt(body.nonce) !== BigInt(session.nonce)) {
        console.error("nonce mismatch");
        res.redirect(400, "/register?message=Nonce+mismatch.");
        await connection.rollback();
        return;
      }
      if ((await connection.query("SELECT 1 from USERS WHERE USERNAME = ?", body.username))[0].length) {
        console.error("user already exists");
        res.redirect(400, "/register?message=User+already+exists.");
        await connection.rollback();
        return;
      }
      await connection.query("INSERT INTO USERS (USERNAME, OUTPUT, NONCE, CATCHPHRASE) VALUES (?, ?, ?, ?)",
          [body.username, body.output, body.nonce, randomWords({min: 5, max: 10, maxLength: 9, join: ' '})]);
      await connection.query(`CREATE TABLE ??
                                  (
                                      UUID     VARCHAR(36)  PRIMARY KEY NOT NULL,
                                      APP      VARCHAR(32)              NOT NULL,
                                      OUTPUT   VARCHAR(100)             NOT NULL,
                                      NONCE    VARCHAR(100)             NOT NULL
                                  );`, [body.username]);
      session.username = body.username;
      console.log("added user", body.username);
      res.redirect("/");
      await connection.commit();
    } catch (e) {
      console.error(e);
      res.redirect(500, "/register?message=Something+went+wrong.");
      await connection.rollback();
    } finally {
      // await connection.query("UNLOCK TABLES");
      session.nonce = generateNonce();
      connection.release();
    }
  });

  app.get("/api/user", async ({query}, res) => {
    let [result] = await pool.query("SELECT OUTPUT, NONCE FROM USERS WHERE USERNAME = ?", [query.username]);
    if (result.length) {
      res.send({
        output: result[0].OUTPUT,
        nonce: result[0].NONCE
      });
    } else {
      res.status(404);
      res.send("User not found");
    }
  });

  app.get("/signin", ({session, query}, res) => {
    res.sendFile("signin.html", {root: __dirname});
  });

  app.get("/update", ({session, query}, res) => {
    if (session.username) {
      res.sendFile("update.html", {root: __dirname});
    } else {
      res.redirect("/signin");
    }
  });

  app.post("/update", async ({body, session}, res) => {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      try {
        BigInt(body.output);
        BigInt(body.nonce);
      } catch (e) {
        console.error("invalid public signals");
        res.redirect(400, "/signin?message=Invalid+public+signals.");
        await connection.rollback();
        return;
      }
      if (!session.nonce) {
        console.error("nonce not generated");
        res.redirect(500, "/signin?message=Nonce+not+generated.");
        await connection.rollback();
        return;
      }
      if (BigInt(body.nonce) !== BigInt(session.nonce)) {
        console.error("nonce mismatch");
        res.redirect(400, "/signin?message=Nonce+mismatch.");
        await connection.rollback();
        return;
      }
      let [result] = await pool.query("SELECT OUTPUT, NONCE FROM USERS WHERE USERNAME = ?", [body.username]);
      if (!result.length) {
        res.redirect(400, "/signin?message=User+not+found.");
        return;
      }
      if (!await snarkjs.plonk.verify(vKey, [result[0].OUTPUT, result[0].NONCE], JSON.parse(body.proof))) {
        res.redirect(400, "/signin?message=Username+or+password+is+incorrect.");
        return;
      }
      await connection.query("UPDATE USERS SET OUTPUT = ?, NONCE = ? WHERE USERNAME = ?",
          [body.output, body.nonce, body.username]);
      session.username = body.username;
      console.log("user", body.username, "updated");
      res.redirect("/");
      await connection.commit();
    } catch (e) {
      console.error(e);
      res.redirect(500, "/signin?message=Something+went+wrong.");
      await connection.rollback();
    } finally {
      session.nonce = generateNonce();
      connection.release();
    }
  });

  app.get("/signout", ({session}, res) => {
    session.destroy();
    res.redirect("/signin");
  });

  app.get("/static/snarkjs.js", (req, res) => {
    res.sendFile(snarkjspath);
  });

  app.get("/static/circuit.wasm", (req, res) => {
    res.sendFile(path.join(__dirname, "../circuit_js/circuit.wasm"));
  });

  app.get("/static/circuit_final.zkey", (req, res) => {
    res.sendFile(path.join(__dirname, "../circuit_final.zkey"));
  });

  app.get("/static/verification_key.json", (req, res) => {
    res.sendFile(path.join(__dirname, "../verification_key.json"));
  });

  app.listen(port, () => {
    console.log(`SSO server listening on port ${port}`);
  });
})();