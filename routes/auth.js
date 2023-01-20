const express = require("express");
const router = new express.Router();
const User = require("../models/user");
const ExpressError = require("../expressError");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const result = await User.authenticate(
      req.body.username,
      req.body.password
    );
    if (!result) throw new ExpressError("Invalid Login", 401);
    await User.updateLoginTimestamp(req.body.username);
    const token = jwt.sign({ username: req.body.username }, SECRET_KEY);
    return res.send(token);
  } catch (e) {
    next(e);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
  try {
    const result = await User.register(
      req.body.username,
      req.body.password,
      req.body.first_name,
      req.body.last_name,
      req.body.phone
    );
    await User.updateLoginTimestamp(req.body.username);
    const token = jwt.sign({ username: req.body.username }, SECRET_KEY);
    return res.send(token);
  } catch (e) {
    next(e);
  }
});

module.exports = router;
