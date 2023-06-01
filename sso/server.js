const express = require("express");
const snarkjs = require("snarkjs");

const pool = require("./pool");
const utils = require("./utils");

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
  app.use("/static", require("../static"));

  app.get("/", ({session}, res) => {
    if (session.username) {
      res.sendFile("index.html", {root: __dirname});
    } else {
      res.redirect("/signin");
    }
  });

  app.get("/register", ({session, query}, res) => {
    if (session.username) {
      res.redirect("/");
    } else {
      res.sendFile("register.html", {root: __dirname});
    }
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
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Invalid public signals.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      if (!session.nonce) {
        console.error("nonce not generated");
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Nonce not generated.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      if (BigInt(body.nonce) !== BigInt(session.nonce)) {
        console.error("nonce mismatch");
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Nonce mismatch.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      if (await utils.getUser(body.username, connection)) {
        console.error("user already exists");
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "User already exists.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      await utils.addUser(body.username, body.output, body.nonce, connection);
      session.username = body.username;
      console.log("added user", body.username);
      res.redirect(body.redirect ? body.redirect : "/");
      await connection.commit();
    } catch (e) {
      console.error(e);
      res.redirect(500, "/register?" + new URLSearchParams({
        message: "Something went wrong.",
        ...body.redirect && {
          redirect: body.redirect
        }
      }));
      await connection.rollback();
    } finally {
      // await connection.query("UNLOCK TABLES");
      session.nonce = utils.randomBigUint64();
      connection.release();
    }
  });

  app.get("/signin", ({session, query}, res) => {
    if (session.username) {
      res.redirect("/");
    } else {
      res.sendFile("signin.html", {root: __dirname});
    }  });

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
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Invalid public signals.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      if (!session.nonce) {
        console.error("nonce not generated");
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Nonce not generated.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      if (BigInt(body.nonce) !== BigInt(session.nonce)) {
        console.error("nonce mismatch");
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Nonce mismatch.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      let user = await utils.getUser(body.username, connection);
      if (!user) {
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "User not found.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        return;
      }
      if (!body.proof) {
        console.error("Missing proof");
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Missing proof.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        await connection.rollback();
        return;
      }
      if (!await snarkjs.plonk.verify(utils.vKey, [
          user.output,
          user.nonce
      ], JSON.parse(body.proof))) {
        res.redirect(400, "/register?" + new URLSearchParams({
          message: "Username or password is incorrect.",
          ...body.redirect && {
            redirect: body.redirect
          }
        }));
        return;
      }
      await utils.updateUser(body.user, body.output, body.nonce, connection);
      session.username = body.username;
      console.log("user", body.username, "updated");
      res.redirect(body.redirect ? body.redirect : "/");
      await connection.commit();
    } catch (e) {
      console.error(e);
      res.redirect(500, "/register?" + new URLSearchParams({
        message: "Something went wrong.",
        ...body.redirect && {
          redirect: body.redirect
        }
      }));
      await connection.rollback();
    } finally {
      session.nonce = utils.randomBigUint64();
      connection.release();
    }
  });

  app.get("/signout", ({session}, res) => {
    session.destroy();
    res.redirect("/signin");
  });

  app.get("/credentials/add", ({session, url}, res) => {
    if (!session.username) {
      res.redirect(`/signin?redirect=${encodeURIComponent(url)}`);
      return;
    }
    res.sendFile("credentials-add.html", {root: __dirname});
  });

  app.post("/credentials/add", async ({body, session}, res) => {
    const connection = await pool.getConnection();
    try {
      if (!session.username) {
        res.status(403);
        res.send("Forbidden");
        await connection.rollback();
        return;
      }
      if (!body.url) {
        res.status(400);
        res.send("Missing url");
        await connection.rollback();
        return;
      }
      if (!utils.urlPattern.test(body.url)) {
        res.status(400);
        res.send("Invalid url");
        await connection.rollback();
        return;
      }
      if (body.url.length > 512) {
        res.status(400);
        res.send("url too long");
        await connection.rollback();
        return;
      }
      // if (!body.uuid) {
      //   res.status(400);
      //   res.send("Missing uuid");
      //   await connection.rollback();
      //   return;
      // }
      // if (body.uuid.length !== 36) {
      //   res.status(400);
      //   res.send("Invalid uuid");
      //   await connection.rollback();
      //   return;
      // }
      // if (!body.otp) {
      //   res.status(400);
      //   res.send("Missing otp");
      //   await connection.rollback();
      //   return;
      // }
      // try {
      //   BigInt(body.otp);
      // } catch (e) {
      //   res.status(400);
      //   res.send("Invalid otp");
      //   await connection.rollback();
      //   return;
      // }
      // if (body.otp.length > 100) {
      //   res.status(400);
      //   res.send("otp too big");
      //   await connection.rollback();
      //   return;
      // }
      if (await utils.getCredential(session.username, body.url, connection)) {
        res.status(400);
        res.send("Credential already exists");
        await connection.rollback();
        return;
      }
      if (!await utils.getApp(body.url, connection)) {
        // if (!body.url) {
        //   res.status(400);
        //   res.send("Missing url");
        //   await connection.rollback();
        //   return;
        // }
        // if (body.url.length > 512) {
        //   res.status(400);
        //   res.send("url too long");
        //   await connection.rollback();
        //   return;
        // }
        if (!body.name) {
          res.status(400);
          res.send("Missing name");
          await connection.rollback();
          return;
        }
        if (body.name.length > 32) {
          res.status(400);
          res.send("name too long");
          await connection.rollback();
          return;
        }
        await utils.addApp(body.url, body.name, connection);
      }
      const otp = utils.randomBigUint64();
      const nonce = utils.randomBigUint64();
      if (!await utils.registerRemoteUser(session.username, body.url, otp, nonce)) {
        res.status(500);
        res.send("app failed to register");
        await connection.rollback();
        return;
      }
      res.redirect(body.redirect ? body.redirect : body.url);
      await utils.addCredential(session.username, body.url, otp, connection);
      await connection.commit();
    } catch (e) {
      console.error(e);
      res.status(500);
      res.send("Something went wrong");
      await connection.rollback();
    } finally {
      connection.release();
    }
  });

  app.get("/credentials/auth", ({session, url}, res) => {
    if (!session.username) {
      res.redirect(`/signin?redirect=${encodeURIComponent(url)}`);
      return;
    }
    res.sendFile("credentials-auth.html", {root: __dirname});
  });

  app.post("/credentials/auth", async ({body, session}, res) => {
    const connection = await pool.getConnection();
    try {
      if (!session.username) {
        res.status(403);
        res.send("Forbidden");
        await connection.rollback();
        return;
      }
      if (!body.url) {
        res.status(400);
        res.send("Missing url");
        await connection.rollback();
        return;
      }
      if (!utils.urlPattern.test(body.url)) {
        res.status(400);
        res.send("Invalid url");
        await connection.rollback();
        return;
      }
      if (body.url.length > 512) {
        res.status(400);
        res.send("url too long");
        await connection.rollback();
        return;
      }
      if (!await utils.getApp(body.url, connection)) {
        res.status(400);
        res.send("App does not exist");
        await connection.rollback();
        return;
      }
      const credential = await utils.getCredential(session.username, body.url, connection);
      if (!credential) {
        res.status(400);
        res.send("Credential does not exist");
        await connection.rollback();
        return;
      }
      let {proof} = await snarkjs.plonk.fullProve({
        password: credential.otp,
        nonce: JSON.parse(await (await fetch(body.url + "/api/user?" + new URLSearchParams({
          username: session.username,
          url: process.env.SSO_URL
        }))).text()).nonce
      }, utils.wasmFile, utils.zKeyFileName);
      let otp = utils.randomBigUint64();
      let nonce = utils.randomBigUint64();
      let {proof: newProof, publicSignals} = await snarkjs.plonk.fullProve({
        password: otp,
        nonce
      }, utils.wasmFile, utils.zKeyFileName);
      // let response = await fetch(body.url + "/api/auth", {
      //   method: "post",
      //   headers: {
      //     'Content-Type': 'application/x-www-form-urlencoded',
      //   },
      //   body: new URLSearchParams({
      //     username: session.username,
      //     url: process.env.SSO_URL,
      //     proof: JSON.stringify(proof),
      //     output: publicSignals[0],
      //     nonce: publicSignals[1]
      //   }).toString()
      // });
      let response = await fetch(body.url + "/api/auth?" + new URLSearchParams({
        username: session.username,
        url: process.env.SSO_URL,
        proof: JSON.stringify(proof),
        output: publicSignals[0],
        nonce: publicSignals[1]
      }));
      if (!response.ok) {
        console.error(await response.text());
        res.status(500);
        res.send("auth error");
        await connection.rollback();
        return;
      }
      let {publicSignals: newPublicSignals} = await snarkjs.plonk.fullProve({
        password: otp,
        nonce: utils.randomBigUint64()
      }, utils.wasmFile, utils.zKeyFileName);
      res.redirect(body.url + "/api/auth?" + new URLSearchParams({
        username: session.username,
        url: process.env.SSO_URL,
        proof: JSON.stringify(newProof),
        output: newPublicSignals[0],
        nonce: newPublicSignals[1],
        ...body.redirect && {
          redirect: body.redirect
        }
      }));
      await utils.updateCredential(session.username, body.url, otp, connection);
      await connection.commit();
    } catch (e) {
      console.error(e);
      res.status(500);
      res.send("Something went wrong");
      await connection.rollback();
    } finally {
      connection.release();
    }
  });

  await pool.ready;

  app.listen(port, () => {
    console.log(`SSO server listening on port ${port}`);
  });
})();