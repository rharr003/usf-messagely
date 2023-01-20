/** User class for message.ly */

const { DB_URI } = require("../config");
const db = require("../db");
const bcrypt = require("bcrypt");

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  constructor({
    user_name,
    password,
    first_name,
    last_name,
    phone,
    join_at,
    last_login_at,
  }) {
    (this.user_name = user_name),
      (this.password = password),
      (this.first_name = first_name),
      (this.last_name = last_name),
      (this.phone = phone),
      (this.join_at = join_at),
      (this.last_login_at = last_login_at);
  }

  static async register(username, password, first_name, last_name, phone) {
    const hashed_password = await bcrypt.hash(password, 12);
    const user = await db.query(
      "INSERT INTO users(username, password, first_name, last_name, phone, join_at) VALUES($1, $2, $3, $4, $5, $6) RETURNING *",
      [username, hashed_password, first_name, last_name, phone, new Date()]
    );
    return new User(user.rows[0]);
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const user = await db.query("SELECT * FROM users WHERE username=$1", [
      username,
    ]);
    if (user.rowCount === 0) return false;
    return await bcrypt.compare(password, user.rows[0].password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const now = new Date();
    const result = await db.query(
      "UPDATE users SET last_login_at=$1 WHERE username=$2 RETURNING username, last_login_at",
      [now, username]
    );
    return {
      updated: {
        username: result.rows[0].username,
        last_login_at: result.rows[0].last_login_at,
      },
    };
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query("SELECT * FROM users");
    const arr = [];
    result.rows.forEach((value) => {
      arr.push(new User(value));
    });
    return arr;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const user = await db.query("SELECT * FROM users WHERE username=$1", [
      username,
    ]);
    if (user.rowCount === 0) return null;
    return new User(user.rows[0]);
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      "SELECT * FROM messages WHERE from_username=$1",
      [username]
    );
    if (results.rowCount === 0) return "No messages found";
    return results.rows;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      "SELECT * FROM messages WHERE to_username=$1",
      [username]
    );
    if (results.rowCount === 0) return "No messages found";
    return results.rows;
  }
}

module.exports = User;
