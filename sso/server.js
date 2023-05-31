const express = require("express");
const snarkjs = require("snarkjs");
const fs = require("fs");
const randomWords = require('random-words');

const pool = require("./pool");

const vKey = JSON.parse(fs.readFileSync("../verification_key.json").toString());

(async () => {
  function generateNonce() {
    return crypto.getRandomValues(new BigUint64Array(1))[0].toString();
  }

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

  app.use("/api", require("./api"));
  app.use("/static", require("./static"));

  app.get("/", ({session}, res) => {
    if (session.username) {
      res.sendFile("index.html", { root: __dirname });
    } else {
      res.redirect("/signin");
    }
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
      if (!await snarkjs.plonk.verify(vKey, [result[0].output, result[0].nonce], JSON.parse(body.proof))) {
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

  await pool.ready;

  app.listen(port, () => {
    console.log(`SSO server listening on port ${port}`);
  });
})();