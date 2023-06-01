const pool = require("./pool");

require("dotenv").config();

module.exports = {
  randomBigUint64() {
    return crypto.getRandomValues(new BigUint64Array(1))[0].toString();
  },
  async addUser(username, url, output, nonce, connection = pool) {
    await connection.query(`
        INSERT INTO users
        (username, url, output, nonce)
        VALUES (?, ?, ?, ?)`,
      [username, url, output, nonce]);
  },
  async getUser(username, url, connection = pool) {
    const [[user]] = await connection.query(`
        SELECT output, nonce
        FROM users
        WHERE (username, url) = (?, ?)`, [username, url]);
    return user;
  },
  async updateUser(username, url, output, nonce, connection = pool) {
    await connection.query(`
        UPDATE users
        SET output = ?, nonce = ?
        WHERE (username, url) = (?, ?)`, [output, nonce, username, url]);
  }
};
