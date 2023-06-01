const express = require("express");

const pool = require("./pool");
const utils = require("./utils");
const fs = require("fs");
const snarkjs = require("snarkjs");

const vKey = JSON.parse(fs.readFileSync("../verification_key.json").toString());

const router = module.exports = express.Router();
router.get("/user", async ({query}, res) => {
  if (!query.username) {
    res.status(400);
    res.send("Missing username");
    return;
  }
  if (!query.url) {
    res.status(400);
    res.send("Missing url");
    return;
  }
  res.send(await utils.getUser(query.username, query.url));
});

router.post("/register", async ({body, session}, res) => {
  const connection = await pool.getConnection();
  try {
    if (!body.username) {
      res.status(400);
      res.send("Missing username");
      await connection.rollback();
      return;
    }
    if (body.username.length > 32) {
      res.status(400);
      res.send("username too long");
      await connection.rollback();
      return;
    }
    if (!body.url) {
      res.status(400);
      res.send("Missing url");
      await connection.rollback();
      return;
    }
    if (body.url.length > 512) {
      res.status(400);
      res.send("url too long");
      await connection.rollback();
      return;
    }
    if (await utils.getUser(body.username, body.url, connection)) {
      res.status(400);
      res.send("User already exists");
      await connection.rollback();
      return;
    }
    if (!body.output) {
      res.status(400);
      res.send("Missing output");
      await connection.rollback();
      return;
    }
    try {
      BigInt(body.output)
    } catch (e) {
      res.status(400);
      res.send("Invalid output");
      await connection.rollback();
      return;
    }
    if (body.output.length > 100) {
      res.status(400);
      res.send("output too large");
      await connection.rollback();
      return;
    }
    if (!body.nonce) {
      res.status(400);
      res.send("Missing nonce");
      await connection.rollback();
      return;
    }
    try {
      BigInt(body.nonce)
    } catch (e) {
      res.status(400);
      res.send("Invalid nonce");
      await connection.rollback();
      return;
    }
    if (body.nonce.length > 100) {
      res.status(400);
      res.send("nonce too large");
      await connection.rollback();
      return;
    }
    await utils.addUser(body.username, body.url, body.output, body.nonce, connection);
    session.username = body.username;
    session.url = body.url;
    res.redirect(body.redirect ? body.redirect : "/");
    await connection.commit();
  } catch (e) {
    console.error(e);
    res.status(500);
    res.send("Something went wrong.");
    await connection.rollback();
  } finally {
    connection.release();
  }
});

router.post("/auth", async ({session, body}, res) => {
  const connection = await pool.getConnection();
  try {
    if (!body.username) {
      res.status(400);
      res.send("Missing username");
      await connection.rollback();
      return;
    }
    if (body.username.length > 32) {
      res.status(400);
      res.send("username too long");
      await connection.rollback();
      return;
    }
    if (!body.url) {
      res.status(400);
      res.send("Missing url");
      await connection.rollback();
      return;
    }
    if (body.url.length > 512) {
      res.status(400);
      res.send("url too long");
      await connection.rollback();
      return;
    }
    const user = await utils.getUser(body.username, body.url, connection);
    if (!user) {
      res.status(400);
      res.send("User does not exist");
      await connection.rollback();
      return;
    }
    if (!body.output) {
      res.status(400);
      res.send("Missing output");
      await connection.rollback();
      return;
    }
    try {
      BigInt(body.output)
    } catch (e) {
      res.status(400);
      res.send("Invalid output");
      await connection.rollback();
      return;
    }
    if (body.output.length > 100) {
      res.status(400);
      res.send("output too large");
      await connection.rollback();
      return;
    }
    if (!body.nonce) {
      res.status(400);
      res.send("Missing nonce");
      await connection.rollback();
      return;
    }
    if (BigInt(body.nonce) === BigInt(user.nonce)) {
      res.status(400);
      res.send("same nonce");
      await connection.rollback();
      return;
    }
    try {
      BigInt(body.nonce)
    } catch (e) {
      res.status(400);
      res.send("Invalid nonce");
      await connection.rollback();
      return;
    }
    if (body.nonce.length > 100) {
      res.status(400);
      res.send("nonce too large");
      await connection.rollback();
      return;
    }
    if (!body.proof) {
      res.status(400);
      res.send("Missing proof");
      await connection.rollback();
      return;
    }
    if (!await snarkjs.plonk.verify(vKey, [
        user.output,
        user.nonce
    ], JSON.parse(body.proof))) {
      res.status(400);
      res.send("Invalid credentials");
      await connection.rollback();
      return;
    }
    await utils.updateUser(body.username, body.url, body.output, body.nonce, connection);
    session.username = body.username;
    session.url = body.url;
    res.redirect(body.redirect ? body.redirect : "/");
    await connection.commit();
  } catch (e) {
    console.error(e);
    res.status(500);
    res.send("Something went wrong.");
    await connection.rollback();
  } finally {
    connection.release();
  }
});

router.get("/auth", async ({session, query}, res) => {
  const connection = await pool.getConnection();
  try {
    if (!query.username) {
      res.status(400);
      res.send("Missing username");
      await connection.rollback();
      return;
    }
    if (query.username.length > 32) {
      res.status(400);
      res.send("username too long");
      await connection.rollback();
      return;
    }
    if (!query.url) {
      res.status(400);
      res.send("Missing url");
      await connection.rollback();
      return;
    }
    if (query.url.length > 512) {
      res.status(400);
      res.send("url too long");
      await connection.rollback();
      return;
    }
    const user = await utils.getUser(query.username, query.url, connection);
    if (!user) {
      res.status(400);
      res.send("User does not exist");
      await connection.rollback();
      return;
    }
    if (!query.output) {
      res.status(400);
      res.send("Missing output");
      await connection.rollback();
      return;
    }
    try {
      BigInt(query.output)
    } catch (e) {
      res.status(400);
      res.send("Invalid output");
      await connection.rollback();
      return;
    }
    if (query.output.length > 100) {
      res.status(400);
      res.send("output too large");
      await connection.rollback();
      return;
    }
    if (!query.nonce) {
      res.status(400);
      res.send("Missing nonce");
      await connection.rollback();
      return;
    }
    if (BigInt(query.nonce) === BigInt(user.nonce)) {
      res.status(400);
      res.send("same nonce");
      await connection.rollback();
      return;
    }
    try {
      BigInt(query.nonce)
    } catch (e) {
      res.status(400);
      res.send("Invalid nonce");
      await connection.rollback();
      return;
    }
    if (query.nonce.length > 100) {
      res.status(400);
      res.send("nonce too large");
      await connection.rollback();
      return;
    }
    if (!query.proof) {
      res.status(400);
      res.send("Missing proof");
      await connection.rollback();
      return;
    }
    if (!await snarkjs.plonk.verify(vKey, [
      user.output,
      user.nonce
    ], JSON.parse(query.proof))) {
      res.status(400);
      res.send("Invalid credentials");
      await connection.rollback();
      return;
    }
    await utils.updateUser(query.username, query.url, query.output, query.nonce, connection);
    session.username = query.username;
    session.url = query.url;
    res.redirect(query.redirect ? query.redirect : "/");
    await connection.commit();
  } catch (e) {
    console.error(e);
    res.status(500);
    res.send("Something went wrong.");
    await connection.rollback();
  } finally {
    connection.release();
  }
});
