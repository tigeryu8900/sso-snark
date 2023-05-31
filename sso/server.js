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

  await pool.query(`CREATE TABLE IF NOT EXISTS users
             (
                 username    VARCHAR(32)  PRIMARY KEY NOT NULL,
                 output      VARCHAR(100)             NOT NULL,
                 nonce       VARCHAR(100)             NOT NULL,
                 catchphrase VARCHAR(100)             NOT NULL
             )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS apps
             (
                 username    VARCHAR(32)              NOT NULL,
                 uuid        CHAR(36)                 NOT NULL,
                 app         VARCHAR(32)              NOT NULL,
                 otp         VARCHAR(100)             NOT NULL,
                 PRIMARY KEY (username, uuid)
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
      let [[{catchphrase}]] = await pool.query("SELECT catchphrase FROM users WHERE username = ?", [session.username]);
      res.send(catchphrase);
    } else {
      res.status(403);
      res.send("Forbidden");
    }
  });

  app.get("/api/apps", async ({session}, res) => {
    if (session.username) {
      let [apps] = await pool.query("SELECT uuid, app FROM apps WHERE username = ?", [session.username]);
      res.send(apps);
    } else {
      res.status(403);
      res.send("Forbidden");
    }
  })

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
      if ((await connection.query("SELECT 1 from users WHERE username = ?", body.username))[0].length) {
        console.error("user already exists");
        res.redirect(400, "/register?message=User+already+exists.");
        await connection.rollback();
        return;
      }
      await connection.query("INSERT INTO users (username, output, nonce, catchphrase) VALUES (?, ?, ?, ?)",
          [body.username, body.output, body.nonce, randomWords({min: 5, max: 10, maxLength: 9, join: ' '})]);

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
    let [result] = await pool.query("SELECT output, nonce FROM users WHERE username = ?", [query.username]);
    if (result.length) {
      res.send(result[0]);
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
      let [result] = await pool.query("SELECT output, nonce FROM users WHERE username = ?", [body.username]);
      if (!result.length) {
        res.redirect(400, "/signin?message=User+not+found.");
        return;
      }
      if (!await snarkjs.plonk.verify(vKey, [result[0].OUTPUT, result[0].NONCE], JSON.parse(body.proof))) {
        res.redirect(400, "/signin?message=Username+or+password+is+incorrect.");
        return;
      }
      await connection.query("UPDATE users SET output = ?, nonce = ? WHERE username = ?",
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