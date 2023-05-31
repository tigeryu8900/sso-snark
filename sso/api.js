const express = require("express");

const pool = require("./pool");

const router = module.exports = express.Router();

router.get("/catchphrase", async ({session}, res) => {
  if (session.username) {
    let [[{catchphrase}]] = await pool.query("SELECT catchphrase FROM users WHERE username = ?", [session.username]);
    res.send(catchphrase);
  } else {
    res.status(403);
    res.send("Forbidden");
  }
});

router.get("/apps", async ({session}, res) => {
  if (session.username) {
    let [apps] = await pool.query(`
        SELECT uuid, name, ip
        FROM apps
        WHERE uuid IN (
            SELECT uuid
            FROM credentials
            WHERE username = ?
        )`, [session.username]);
    res.send(apps);
  } else {
    res.status(403);
    res.send("Forbidden");
  }
});

router.get("/nonce", ({session}, res) => {
  session.nonce = crypto.getRandomValues(new BigUint64Array(1))[0].toString();
  res.send(session.nonce);
});

router.get("/user", async ({query}, res) => {
  let [result] = await pool.query("SELECT output, nonce FROM users WHERE username = ?", [query.username]);
  if (result.length) {
    res.send(result[0]);
  } else {
    res.status(404);
    res.send("User not found");
  }
});
