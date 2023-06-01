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
  res.send(await utils.getCatchphrase(session.username));
});

router.get("/apps", async ({session}, res) => {
  if (!session.username) {
    res.status(403);
    res.send("Forbidden");
    return;
  }
  res.send(await utils.getApps(session.username));
});

router.get("/nonce", ({session}, res) => {
  session.nonce = utils.randomBigUint64();
  res.send(session.nonce);
});

router.get("/user", async ({query}, res) => {
  if (!query.username) {
    res.status(400);
    res.send("Missing username");
    return;
  }
  let user = await utils.getUser(query.username);
  if (!user) {
    res.status(404);
    res.send("User not found");
    return;
  }
  res.send(user);
});

router.get("/app", async ({query}, res) => {
  if (!query.url) {
    res.status(400);
    res.send("Missing url");
    return;
  }
  let app = utils.getApp(query.url);
  if (!app) {
    res.status(404);
    res.send("App not found");
    return;
  }
  res.send(app);
});
