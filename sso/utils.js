const randomWords = require("random-words");
const snarkjs = require("snarkjs");
// const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const pool = require("./pool");

require("dotenv").config();

module.exports = {
  urlPattern: /^https?:\/\/(?:(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]|localhost)\b(?:[-a-zA-Z0-9()@:%_\+.~&\/=]*[-a-zA-Z0-9()@:%_\+.~&=])?$/,
  randomBigUint64() {
    return crypto.getRandomValues(new BigUint64Array(1))[0].toString();
  },
  async addUser(username, output, nonce, connection = pool) {
    await connection.query(`
          INSERT INTO users
          (username, output, nonce, catchphrase)
          VALUES (?, ?, ?, ?)`,
        [
          username,
          output,
          nonce,
          randomWords({min: 5, max: 10, maxLength: 9, join: ' '})
        ]);
  },
  async getUser(username, connection = pool) {
    let [[user]] = await connection.query(`
        SELECT output, nonce
        FROM users
        WHERE username = ?`, [username]);
    return user;
  },
  async updateUser(username, output, nonce, connection = pool) {
    await connection.query(`
           UPDATE users
           SET output = ?, nonce = ?
           WHERE username = ?`,
        [output, nonce, username]);
  },
  async getCatchphrase(username, connection = pool) {
    let [[{catchphrase}]] = await connection.query(`
        SELECT catchphrase
        FROM users
        WHERE username = ?`, [username]);
    return catchphrase;
  },
  async getApps(username, connection = pool) {
    let [apps] = await connection.query(`
        SELECT url, name
        FROM apps
        WHERE url IN (
            SELECT url
            FROM credentials
            WHERE username = ?
        )`, [username]);
    return apps;
  },
  async addApp(url, name, connection = pool) {
    await connection.query(`
        INSERT INTO apps
        (url, name)
        VALUES (?, ?)`, [url, name]);
  },
  async getApp(url, connection = pool) {
    let [[app]] = await connection.query(`
        SELECT name
        FROM apps
        WHERE url = ?`, [url]);
    return app;
  },
  async addCredential(username, url, otp, connection = pool) {
    await connection.query(`
        INSERT INTO credentials
        (username, url, otp)
        VALUES (?, ?, ?)`, [username, url, otp]);
  },
  async getCredential(username, url, connection = pool) {
    let [[credential]] = await connection.query(`
        SELECT otp
        FROM credentials
        WHERE (username, url) = (?, ?)`, [username, url]);
    return credential;
  },
  async updateCredential(username, url, otp, connection = pool) {
    await connection.query(`
        UPDATE credentials
        SET otp = ?
        WHERE (username, url) = (?, ?)`, [otp, username, url]);
  },
  async registerRemoteUser(username, url, otp, nonce) {
    const [output] = (await snarkjs.plonk.fullProve({
      password: otp,
      nonce
    }, "../circuit_js/circuit.wasm", "../circuit_final.zkey")).publicSignals;
    const response = await fetch(url + "/api/register", {
      method: "post",
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        username,
        url: process.env.SSO_URL,
        output,
        nonce
      }).toString()
    });
    return response.ok;
  }
};
