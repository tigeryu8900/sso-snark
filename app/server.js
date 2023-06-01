const express = require("express");
const path = require("path");
const fs = require("fs");

const pool = require("./pool");

require("dotenv").config();

(async () => {
  const app = express();
  const port = 8080;

  app.use(express.json());
  app.use(express.urlencoded({extended: true}));
  app.use(require("cookie-parser")());
  app.use(require("express-session")({
    secret: "tigerthegreat",
    saveUninitialized: false,
    cookie: {maxAge: 1000 * 60 * 60 * 24},
    resave: false
  }));

  app.use("/static", require("../static"));
  app.use("/api", require("./api"));

  app.get("/", ({session}, res) => {
    if (session.username) {
      res.sendFile("index.html", {root: __dirname});
    } else {
      res.redirect("/signin");
    }
  });

  app.get("/register", ({session}, res) => {
    if (session.username) {
      res.redirect("/");
    } else {
      res.sendFile("register.html", {root: __dirname});
    }
  });

  app.get("/signin", ({session}, res) => {
    res.sendFile("signin.html", {root: __dirname});
  });

  app.get("/signout", ({session}, res) => {
    session.destroy();
    res.redirect("/signin");
  });

  await pool.ready;

  app.listen(port, () => {
    console.log(`App server listening on port ${port}`);
  });
})();
