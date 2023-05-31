const express = require("express");
const snarkjs = require("snarkjs");
const fs = require("fs");

const pool = require("./pool");
const utils = require("./utils");

const vKey = JSON.parse(fs.readFileSync("../verification_key.json").toString());

(async () => {
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
      if (await utils.getUser(body.username, connection)) {
        console.error("user already exists");
        res.redirect(400, "/register?message=User+already+exists.");
        await connection.rollback();
        return;
      }
      await utils.addUser(body.username, body.output, body.nonce, connection);
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
      session.nonce = utils.generateNonce();
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
      let user = await utils.getUser(body.username, connection);
      if (!user) {
        res.redirect(400, "/signin?message=User+not+found.");
        return;
      }
      if (!await snarkjs.plonk.verify(vKey, [
          user.output,
          user.nonce
      ], JSON.parse(body.proof))) {
        res.redirect(400, "/signin?message=Username+or+password+is+incorrect.");
        return;
      }
      await utils.updateUser(body.user, body.output, body.nonce, connection);
      session.username = body.username;
      console.log("user", body.username, "updated");
      res.redirect("/");
      await connection.commit();
    } catch (e) {
      console.error(e);
      res.redirect(500, "/signin?message=Something+went+wrong.");
      await connection.rollback();
    } finally {
      session.nonce = utils.generateNonce();
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