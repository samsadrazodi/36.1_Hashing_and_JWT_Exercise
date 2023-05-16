/** User class for message.ly */

const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");

const { BCRYPT_WORK_FACTOR } = require("../config");


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

    const result = await db.query(
      `INSERT INTO users
          (username,
           password,
           first_name,
           last_name,
           phone,
           join_at,
           last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone],
    );
    return result.rows[0];
   }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT password
        FROM users
        WHERE username = $1`,
      [username],
    );
    const user = result.rows[0];

    if (user) {
      return await bcrypt.compare(password, user.password) === true;
    }

    throw new ExpressError('Invalid username/password', 401);
  
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
        SET last_login_at = current_timestamp
        WHERE username = $1
        RETURNING username`,
      [username],
    );

    if (!result.rows[0]) {
      throw new ExpressError(`No user: ${username}`, 404);
    }
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username,
              first_name,
              last_name,
              phone
        FROM users
        ORDER BY username`,
    );
    return result.rows;
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
    const result = await db.query(
      `SELECT username,
              first_name,
              last_name,
              phone,
              join_at,
              last_login_at
        FROM users
        WHERE username = $1`,
      [username],
    );
    const user = result.rows[0];

    if (!user) {
      throw new ExpressError(`No user: ${username}`, 404);
    }

    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id,
              m.to_username AS to_user,
              u.first_name AS to_first_name,
              u.last_name AS to_last_name,
              u.phone AS to_phone,
              m.body,
              m.sent_at,
              m.read_at
        FROM messages AS m
          JOIN users AS u ON m.to_username = u.username
        WHERE from_username = $1`,
      [username],
    );

    return result.rows.map(row => ({
      id: row.id,
      to_user: {
        username: row.to_user,
        first_name: row.to_first_name,
        last_name: row.to_last_name,
        phone: row.to_phone,
      },
      body: row.body,
      sent_at: row.sent_at,
      read_at: row.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `SELECT m.id,
              m.from_username AS from_user,
              u.first_name AS from_first_name,
              u.last_name AS from_last_name,
              u.phone AS from_phone,
              m.body,
              m.sent_at,
              m.read_at
        FROM messages AS m
          JOIN users AS u ON m.from_username = u.username
        WHERE to_username = $1`,
      [username],
    );

    return result.rows.map(row => ({
      id: row.id,
      from_user: {
        username: row.from_user,
        first_name: row.from_first_name,
        last_name: row.from_last_name,
        phone: row.from_phone,
      },
      body: row.body,
      sent_at: row.sent_at,
      read_at: row.read_at,
    }));
   }
}


module.exports = User;