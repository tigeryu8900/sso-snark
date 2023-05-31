const express = require("express");
const path = require("path");
const snarkjs = require("snarkjs");
const fs = require("fs");
const randomWords = require('random-words');

require("dotenv").config();

const vKey = JSON.parse(fs.readFileSync("../verification_key.json").toString());

(async () => {
  const snarkjspath = path.join(path.dirname(require.resolve('snarkjs')), "snarkjs.js");

  function generateNonce() {
    return crypto.getRandomValues(new BigUint64Array(1))[0].toString();
  }

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



  app.get("/static/snarkjs.js", (req, res) => {
    res.sendFile(snarkjspath);
  });

  app.get("/static/circuit.wasm", (req, res) => {
    res.sendFile(path.join(__dirname, "../circuit_js/circuit.wasm"));
  });

  app.get("/static/circuit_final.zkey", (req, res) => {
    res.sendFile(path.join(__dirname, "../circuit_final.zkey"));
  });

  app.get("/static/verification_key.json", (req, res) => {
    res.sendFile(path.join(__dirname, "../verification_key.json"));
  });

  app.listen(port, () => {
    console.log(`App server listening on port ${port}`);
  });
})();