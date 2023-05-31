const randomWords = require("random-words");

const pool = require("./pool");

module.exports = {
  generateNonce() {
    return crypto.getRandomValues(new BigUint64Array(1))[0].toString()
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
        SELECT uuid, name, ip
        FROM apps
        WHERE uuid IN (
            SELECT uuid
            FROM credentials
            WHERE username = ?
        )`, [username]);
    return apps;
  },
  async addApp(uuid, name, ip, connection = pool) {
    await connection.query(`
        INSERT INTO apps
        (uuid, name, ip)
        VALUES (?, ?, ?)`, [uuid, name, ip]);
  },
  async getApp(uuid, connection = pool) {
    let [[app]] = await connection.query(`
        SELECT uuid, name, ip
        FROM apps
        WHERE uuid = ?`, [uuid]);
    return app;
  },
  async addCredential(username, uuid, otp, connection = pool) {
    await connection.query(`
        INSERT INTO credentials
        (username, uuid, otp)
        VALUES (?, ?, ?)`, [username, uuid, otp]);
  },
  async getCredential(username, uuid, connection = pool) {
    let [[credential]] = connection.query(`
        SELECT otp
        FROM credentials
        WHERE (username, uuid) = (?, ?)`, [username, uuid]);
  }
};
