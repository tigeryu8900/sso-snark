const express = require("express");

const pool = require("./pool");
const utils = require("./utils");

const router = module.exports = express.Router();

router.get("/catchphrase", async ({session}, res) => {
  if (!session.username) {
    res.status(403);
    res.send("Forbidden");
    return;
  }
  res.send(utils.getCatchphrase(session.username));
});

router.get("/apps", async ({session}, res) => {
  if (!session.username) {
    res.status(403);
    res.send("Forbidden");
    return;
  }
  res.send(utils.getApps(session.username));
});

router.get("/nonce", ({session}, res) => {
  session.nonce = utils.generateNonce();
  res.send(session.nonce);
});

router.get("/user", async ({query}, res) => {
  if (!query.username) {
    res.status(400);
    res.send("Missing username");
    return;
  }
  let user = utils.getUser(query.username);
  if (!user) {
    res.status(404);
    res.send("User not found");
    return;
  }
  res.send(user);
});

router.post("/credentials/add", async ({query, session}, res) => {
  const connection = await pool.getConnection();
  try {
    if (!session.username) {
      res.status(403);
      res.send("Forbidden");
      await connection.rollback();
      return;
    }
    if (!query.uuid) {
      res.status(400);
      res.send("Missing uuid");
      await connection.rollback();
      return;
    }
    if (query.uuid.length !== 36) {
      res.status(400);
      res.send("Invalid uuid");
      await connection.rollback();
      return;
    }
    if (!query.otp) {
      res.status(400);
      res.send("Missing otp");
      await connection.rollback();
      return;
    }
    try {
      BigInt(query.otp);
    } catch (e) {
      res.status(400);
      res.send("Invalid otp");
      await connection.rollback();
      return;
    }
    if (query.otp.length > 100) {
      res.status(400);
      res.send("otp too big");
      await connection.rollback();
      return;
    }
    if (await utils.getCredential(session.username, query.uuid, connection)) {
      res.status(400);
      res.send("Credential already exists");
      await connection.rollback();
      return;
    }
    let app = await utils.getApp(query.uuid, connection);
    if (!app) {
      if (!query.name) {
        res.status(400);
        res.send("Missing name");
        await connection.rollback();
        return;
      }
      if (query.name.length > 32) {
        res.status(400);
        res.send("name too long");
        await connection.rollback();
        return;
      }
      if (!query.ip) {
        res.status(400);
        res.send("Missing ip");
        await connection.rollback();
        return;
      }
      if (query.ip.length > 16) {
        res.status(400);
        res.send("ip too long");
        await connection.rollback();
        return;
      }
      await utils.addApp(query.uuid, query.name, query.ip, connection);
      app = query;
    }
    await utils.addCredential(session.username, app.uuid, query.otp, connection);
  } catch (e) {
    console.error(e);
    await connection.rollback();
  } finally {
    connection.release();
  }
});
