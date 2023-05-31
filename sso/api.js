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
  let user = await utils.getUser(query.username);
  if (!user) {
    res.status(404);
    res.send("User not found");
    return;
  }
  res.send(user);
});

router.get("/app", async ({query}, res) => {
  if (!query.uuid) {
    res.status(400);
    res.send("Missing uuid");
    return;
  }
  let app = utils.getApp(query.uuid);
  if (!app) {
    res.status(404);
    res.send("App not found");
    return;
  }
  res.send(app);
});
