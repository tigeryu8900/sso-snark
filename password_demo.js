const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const vKey = JSON.parse(fs.readFileSync(path.join(__dirname, "verification_key.json")).toString());

class App {
  #users;

  constructor() {
    this.#users = {};
  }

  generateNonce() {
    return Math.floor(65536 * Math.random());
  }

  register(username, publicSignals) {
    if (this.#users.hasOwnProperty(username)) {
      throw new Error(`${username} is taken.`);
    }

    this.#users[username] = {
      publicSignals,
      newNonce: this.generateNonce()
    };

    console.log(`Created user ${username}.`)
  }

  getUser(username) {
    if (!this.#users.hasOwnProperty(username)) {
      throw new Error(`${username} doesn't exist.`);
    }

    return this.#users[username];
  }

  async signinOrUpdate(username, proof, newPublicSignals, update = false) {
    if (!this.#users.hasOwnProperty(username)) {
      throw new Error(`${username} doesn't exist.`);
    }

    let user = this.#users[username];

    if (BigInt(newPublicSignals[1]) === BigInt(user.newNonce) &&
        await snarkjs.plonk.verify(vKey, user.publicSignals, proof)) {
      user.publicSignals = newPublicSignals;
      user.newNonce = this.generateNonce();
      console.log(`${username} successfully ${update ? "updated password" : "signed in"}.`);
      return true;
    }

    console.log(`${username} failed to ${update ? "update password" : "sign in"}.`);
    return false;
  }
}

function encode(str) {
  return BigInt("0x" + str.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0').slice(-2)).join(''));
}

async function register(password, nonce) {
  return (await snarkjs.plonk.fullProve({
    password: encode(password),
    nonce
  }, "circuit_js/circuit.wasm", "circuit_final.zkey")).publicSignals;
}

async function signin(user, password, check = true) {
  let proof = (await snarkjs.plonk.fullProve({
    password: encode(password),
    nonce: user.publicSignals[1]
  }, "circuit_js/circuit.wasm", "circuit_final.zkey")).proof;

  if (check && !await snarkjs.plonk.verify(vKey, user.publicSignals, proof)) {
    throw new Error("Password is incorrect.");
  }

  return {
    proof,
    newPublicSignals: (await snarkjs.plonk.fullProve({
      password: encode(password),
      nonce: user.newNonce
    }, "circuit_js/circuit.wasm", "circuit_final.zkey")).publicSignals
  };
}

async function updatePassword(user, password, newPassword, check = true) {
  let proof = (await snarkjs.plonk.fullProve({
    password: encode(password),
    nonce: user.publicSignals[1]
  }, "circuit_js/circuit.wasm", "circuit_final.zkey")).proof;

  if (check && !await snarkjs.plonk.verify(vKey, user.publicSignals, proof)) {
    throw new Error("Password is incorrect.");
  }

  return {
    proof,
    newPublicSignals: (await snarkjs.plonk.fullProve({
      password: encode(newPassword),
      nonce: user.newNonce
    }, "circuit_js/circuit.wasm", "circuit_final.zkey")).publicSignals
  };
}

(async () => {
  const app = new App();

  {
    console.log("Create user Alice.");
    let nonce = app.generateNonce();
    let publicSignals = await register("alice123", nonce);
    app.register("Alice", publicSignals);
  }

  {
    console.log("Create user Bob.");
    let nonce = app.generateNonce();
    let publicSignals = await register("bob123", nonce);
    app.register("Bob", publicSignals);
  }

  {
    console.log("Alice signs in.");
    let user = app.getUser("Alice");
    let {proof, newPublicSignals} = await signin(user, "alice123");
    await app.signinOrUpdate("Alice", proof, newPublicSignals);
  }

  {
    console.log("Bob tries to sign in as Alice.")
    let user = app.getUser("Alice");
    let {proof, newPublicSignals} = await signin(user, "bob123", false);
    await app.signinOrUpdate("Alice", proof, newPublicSignals);
  }

  {
    console.log("Alice changes password.")
    let user = app.getUser("Alice");
    let {proof, newPublicSignals} = await updatePassword(user, "alice123", "alice456");
    await app.signinOrUpdate("Alice", proof, newPublicSignals, true);
  }

  {
    console.log("Alice tries to sign in with old password.");
    let user = app.getUser("Alice");
    let {proof, newPublicSignals} = await signin(user, "alice123", false);
    await app.signinOrUpdate("Alice", proof, newPublicSignals);
  }

  {
    console.log("Alice signs in with new password.")
    let user = app.getUser("Alice");
    let {proof, newPublicSignals} = await signin(user, "alice456");
    await app.signinOrUpdate("Alice", proof, newPublicSignals);
  }
})().then(() => process.exit());
