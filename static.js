const express = require("express");
const path = require("path");

const router = module.exports = express.Router();
const snarkjspath = path.join(path.dirname(require.resolve('snarkjs')), "snarkjs.js");

router.get("/snarkjs.js", (req, res) => {
  res.sendFile(snarkjspath);
});

router.get("/circuit.wasm", (req, res) => {
  res.sendFile(path.join(__dirname, "./circuit_js/circuit.wasm"));
});

router.get("/circuit_final.zkey", (req, res) => {
  res.sendFile(path.join(__dirname, "./circuit_final.zkey"));
});

router.get("/verification_key.json", (req, res) => {
  res.sendFile(path.join(__dirname, "./verification_key.json"));
});
